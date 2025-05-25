# File: analyzer.py
import json
import os
import time
import matplotlib
matplotlib.use('Agg') # Use Agg backend for non-GUI environments
import matplotlib.pyplot as plt
import numpy as np
import asyncio
import base64
from collections import defaultdict, OrderedDict
import statistics
import argparse
import random
import oqs # Needed to get theoretical signature size

# Import from common.py
from common import (
    GENERATED_PACKETS_FILE,
    VERIFIED_PACKETS_FILE, # Log from controller
    OUTPUT_DIR, PQC_SIG_ALG, # Need alg to get theoretical size
    setup_logging,
    b64_decode_to_bytes
)

log = setup_logging("Analyzer")

# --- OQS Setup (to get signature size) ---
SIG_INSTANCE = None
THEORETICAL_SIG_SIZE = 0
try:
    SIG_INSTANCE = oqs.Signature(PQC_SIG_ALG)
    # Determine theoretical signature size based on FIPS 204 spec / common knowledge
    if PQC_SIG_ALG == "ML-DSA-44": THEORETICAL_SIG_SIZE = 2420
    elif PQC_SIG_ALG == "ML-DSA-65": THEORETICAL_SIG_SIZE = 3309
    elif PQC_SIG_ALG == "ML-DSA-87": THEORETICAL_SIG_SIZE = 4627
    else:
        # Attempt to get dynamically (may not work reliably for all algs/wrappers)
        try:
            # This might require creating a dummy keypair/sig if not a class property
            # Placeholder - replace if a reliable dynamic method exists for your oqs version
             dummy_signer = oqs.Signature(PQC_SIG_ALG)
             dummy_pk = dummy_signer.generate_keypair()
             dummy_sk = dummy_signer.export_secret_key()
             dummy_sig = dummy_signer.sign(b"test")
             THEORETICAL_SIG_SIZE = len(dummy_sig)
             log.warning(f"Dynamically determined signature size for {PQC_SIG_ALG}: {THEORETICAL_SIG_SIZE} bytes. Verify this is correct.")
        except Exception as dyn_e:
            log.error(f"Could not determine theoretical signature size dynamically for {PQC_SIG_ALG}: {dyn_e}. Size analysis will be inaccurate.")

    if THEORETICAL_SIG_SIZE > 0:
        log.info(f"Using theoretical signature size for {PQC_SIG_ALG}: {THEORETICAL_SIG_SIZE} bytes")
    else:
        log.error(f"Failed to determine theoretical signature size for {PQC_SIG_ALG}. Packet size/expansion analysis will be inaccurate.")

except Exception as e:
    log.error(f"OQS Init Error: {e}. Cannot determine theoretical signature size.")


# --- Analysis Functions ---

def analyze_packet_data():
    """Analyzes generated packet sizes and verification results from the subsystem model."""
    log.info("Analyzing generated packet sizes and verification results...")
    original_packets_data = {} # {packet_id: size}
    verified_results = {} # {packet_id: {"status": str, "verify_latency": float, "num_subpackets": int}}
    total_verified = 0
    total_failed = 0
    verification_latencies = [] # Latency for verifying the whole packet (all sub-sigs)

    # 1. Load Generated Packets (for original size)
    try:
        with open(GENERATED_PACKETS_FILE, 'r') as f:
            original_packets = json.load(f)
        log.info(f"Loaded {len(original_packets)} original packets from {GENERATED_PACKETS_FILE}")
        for packet in original_packets:
            packet_id = packet.get("packet_id")
            if packet_id:
                try:
                    packet_json = json.dumps(packet)
                    original_packets_data[packet_id] = len(packet_json.encode('utf-8'))
                except Exception as e:
                    log.error(f"Error getting size for original packet {packet_id}: {e}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error(f"Cannot load {GENERATED_PACKETS_FILE}: {e}. Analysis cannot proceed.")
        return None

    # 2. Load Verified Packets (for status, latency, num_subpackets)
    try:
        with open(VERIFIED_PACKETS_FILE, 'r') as f:
            verified_log = json.load(f)
        log.info(f"Loaded {len(verified_log)} verification log entries from {VERIFIED_PACKETS_FILE}")
        for entry in verified_log:
            packet_id = entry.get("packet_id")
            status = entry.get("verification_status")
            latency = entry.get("controller_verification_latency_sec")
            num_subs = entry.get("num_subpackets")
            if packet_id and status and num_subs is not None:
                 # Store only the first verification attempt for a packet_id if duplicates exist
                 if packet_id not in verified_results:
                    verified_results[packet_id] = {"status": status, "verify_latency": latency, "num_subpackets": num_subs}
                    if status == "Success":
                        total_verified += 1
                        if latency is not None:
                            verification_latencies.append(latency)
                    else:
                        total_failed += 1
                 else:
                     log.warning(f"Duplicate verification entry found for packet {packet_id}. Keeping first.")
            else:
                 log.warning(f"Skipping invalid verification log entry: {entry}")

    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.warning(f"Could not load verified packets file {VERIFIED_PACKETS_FILE}: {e}. Analysis may be incomplete.")
        # Proceed even if verification log is missing, some analysis is still possible

    # 3. Combine and Calculate Results
    results = {
        "packets_generated": len(original_packets_data),
        "packets_verification_attempted": len(verified_results),
        "packets_verified_successfully": total_verified,
        "packets_verification_failed": total_failed,
        "original_sizes": [],
        "num_subpackets_list": [], # List of subpacket counts for analyzed packets
        "estimated_signed_sizes": [], # Original + N * Theoretical Sig Size
        "expansion_ratios": [], # Based on estimated size
        "controller_verification_latencies": verification_latencies,
        "per_packet": {} # Store combined info
    }

    processed_packet_ids = set(verified_results.keys()) & set(original_packets_data.keys())
    results["packets_analyzed_end_to_end"] = len(processed_packet_ids)

    if THEORETICAL_SIG_SIZE <= 0:
        log.error("Theoretical signature size is unknown. Cannot calculate estimated signed sizes or expansion ratios.")

    for packet_id in processed_packet_ids:
        original_size = original_packets_data[packet_id]
        verify_info = verified_results[packet_id]
        num_subpackets = verify_info["num_subpackets"]

        estimated_signed_size = -1
        expansion_ratio = -1
        if THEORETICAL_SIG_SIZE > 0:
            estimated_signed_size = original_size + (num_subpackets * THEORETICAL_SIG_SIZE)
            expansion_ratio = estimated_signed_size / original_size if original_size > 0 else 0

        results["original_sizes"].append(original_size)
        results["num_subpackets_list"].append(num_subpackets)
        if verify_info["status"] == "Success": # Only include successful packets in size/ratio stats
            if estimated_signed_size != -1: results["estimated_signed_sizes"].append(estimated_signed_size)
            if expansion_ratio != -1: results["expansion_ratios"].append(expansion_ratio)

        results["per_packet"][packet_id] = {
            "original_size": original_size,
            "num_subpackets": num_subpackets,
            "estimated_signed_size": estimated_signed_size if estimated_signed_size != -1 else "N/A",
            "expansion_ratio": expansion_ratio if expansion_ratio != -1 else "N/A",
            "verification_status": verify_info["status"],
            "controller_verify_latency": verify_info["verify_latency"]
        }

    # Calculate overall averages
    if results["original_sizes"]:
        try: results["avg_original_size"] = statistics.mean(results["original_sizes"])
        except: results["avg_original_size"] = 0
    if results["num_subpackets_list"]:
         try: results["avg_num_subpackets"] = statistics.mean(results["num_subpackets_list"])
         except: results["avg_num_subpackets"] = 0
    else: results["avg_num_subpackets"] = 0

    if results["estimated_signed_sizes"]:
        try: results["avg_estimated_signed_size"] = statistics.mean(results["estimated_signed_sizes"])
        except: results["avg_estimated_signed_size"] = 0
    if results["expansion_ratios"]:
        try: results["avg_expansion_ratio"] = statistics.mean(results["expansion_ratios"])
        except: results["avg_expansion_ratio"] = 0
    if results["controller_verification_latencies"]:
         try:
             stats = {
                 "avg": statistics.mean(verification_latencies),
                 "median": statistics.median(verification_latencies),
                 "stdev": statistics.stdev(verification_latencies) if len(verification_latencies) > 1 else 0.0,
                 "min": min(verification_latencies),
                 "max": max(verification_latencies),
                 "count": len(verification_latencies)
             }
             results["controller_verification_latency_stats"] = stats
         except Exception as e:
              log.error(f"Could not calculate verification latency stats: {e}")
              results["controller_verification_latency_stats"] = {"error": str(e)}

    log.info(f"Packet data analysis complete. Analyzed {results['packets_analyzed_end_to_end']} packets end-to-end.")
    return results


def plot_packet_size_analysis(results):
    """Plots original vs estimated signed size and expansion ratio."""
    if not results or results["packets_analyzed_end_to_end"] == 0:
        log.error("No valid packet data results to plot"); return
    if THEORETICAL_SIG_SIZE <= 0:
        log.error("Cannot plot packet size comparisons without theoretical signature size."); return

    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)

    # Data for plotting (only use packets analyzed end-to-end)
    packet_ids = sorted(list(results["per_packet"].keys()))
    original_sizes = [results["per_packet"][pid]["original_size"] for pid in packet_ids]
    # Recalculate based on per-packet subpacket count
    estimated_signed_sizes = [results["per_packet"][pid]["original_size"] + (results["per_packet"][pid]["num_subpackets"] * THEORETICAL_SIG_SIZE) for pid in packet_ids]
    expansion_ratios = [(est_size / orig_size) if orig_size > 0 else 0 for est_size, orig_size in zip(estimated_signed_sizes, original_sizes)]

    # Plot 1: Original vs Estimated Signed Size
    try:
        plt.figure(figsize=(max(10, len(packet_ids)*0.6), 6))
        bar_width = 0.35; x = np.arange(len(packet_ids))
        plt.bar(x - bar_width/2, original_sizes, bar_width, label='Original Size (Bytes)')
        plt.bar(x + bar_width/2, estimated_signed_sizes, bar_width, label=f'Est. Signed Size (Orig + N * {THEORETICAL_SIG_SIZE} B Sig)')
        plt.xlabel('Packet ID'); plt.ylabel('Size (bytes)')
        plt.title(f'Packet Size: Original vs Estimated Signed ({PQC_SIG_ALG} - Subsystem Model)')
        plt.xticks(x, packet_ids, rotation=90, fontsize=8)
        plt.legend(); plt.grid(axis='y', linestyle='--', alpha=0.6); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'packet_size_comparison.png')
        plt.savefig(plot_path); plt.close(); log.info(f"Saved packet size comparison plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting packet size comparison: {e}")

    # Plot 2: Expansion Ratio
    try:
        plt.figure(figsize=(max(10, len(packet_ids)*0.5), 5))
        plt.bar(packet_ids, expansion_ratios, color='green', alpha=0.7)
        if "avg_expansion_ratio" in results:
            plt.axhline(y=results["avg_expansion_ratio"], color='r', linestyle='--', label=f'Avg Ratio: {results["avg_expansion_ratio"]:.2f}x')
        plt.xlabel('Packet ID'); plt.ylabel('Expansion Ratio (Est. Signed / Original)')
        plt.title('Packet Size Expansion Ratio (Based on Theoretical Signature Size)')
        plt.xticks(rotation=90, fontsize=8); plt.legend(); plt.grid(axis='y', linestyle='--', alpha=0.6); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'expansion_ratios.png'); plt.savefig(plot_path); plt.close(); log.info(f"Saved expansion ratio plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting expansion ratios: {e}")

    # Plot 3: Average Composition Pie Chart
    try:
        if "avg_original_size" in results and "avg_num_subpackets" in results and THEORETICAL_SIG_SIZE > 0:
            plt.figure(figsize=(7, 7))
            avg_original = results["avg_original_size"]
            avg_num_subs = results["avg_num_subpackets"]
            avg_total_signature_overhead = avg_num_subs * THEORETICAL_SIG_SIZE
            if avg_original > 0 or avg_total_signature_overhead > 0:
                labels = ['Avg Original Data', f'Avg Total Signature Overhead\n({avg_num_subs:.1f} x {THEORETICAL_SIG_SIZE} B)']
                sizes = [avg_original, avg_total_signature_overhead]
                colors = ['lightblue', 'coral']
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
                plt.title(f'Average Composition of Signed Packet\n(Subsystem Model - {PQC_SIG_ALG})')
                plt.tight_layout()
                plot_path = os.path.join(plots_dir, 'average_composition.png'); plt.savefig(plot_path); plt.close()
                log.info(f"Saved average composition plot to {plot_path}")
            else: log.warning("Average sizes are zero, skipping composition pie chart.")
        else: log.warning("Missing average data or signature size for composition pie chart.")
    except Exception as e: log.error(f"Error plotting average composition: {e}")


def plot_verification_latency(results):
    """Plots controller verification latency distribution (latency to verify all sub-sigs)."""
    if not results or "controller_verification_latency_stats" not in results or results["controller_verification_latency_stats"].get("count", 0) == 0:
        log.warning("No verification latency data to plot.")
        return
    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)
    latencies = results.get("controller_verification_latencies", [])
    stats = results["controller_verification_latency_stats"]

    try:
        plt.figure(figsize=(10, 6))
        plt.hist(latencies, bins=20, alpha=0.75, color='purple', edgecolor='black')
        if "error" not in stats:
            plt.axvline(stats.get("avg", 0), color='red', linestyle='dashed', linewidth=1, label=f'Avg: {stats.get("avg", 0):.6f}s')
            plt.axvline(stats.get("median", 0), color='green', linestyle='dashed', linewidth=1, label=f'Median: {stats.get("median", 0):.6f}s')
            plt.legend()
        plt.xlabel('Total Verification Latency per Packet (seconds)')
        plt.ylabel('Number of Packets')
        plt.title(f'Controller Packet Verification Latency Distribution ({PQC_SIG_ALG} - Subsystem Model)')
        plt.grid(axis='y', linestyle='--', alpha=0.6)
        plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'controller_packet_verification_latency.png') # New name
        plt.savefig(plot_path); plt.close(); log.info(f"Saved packet verification latency plot to {plot_path}")
    except Exception as e:
        log.error(f"Error plotting verification latency histogram: {e}")


# --- Network Analysis ---
# BandwidthSimulator class remains the same as before
class BandwidthSimulator:
    def __init__(self):
        self.bandwidth_profiles = {
             "ble_1m": {"bandwidth_kbps": 1000, "latency_ms": 100}, "zigbee": {"bandwidth_kbps": 250, "latency_ms": 50},
             "lora_sf7_125k": {"bandwidth_kbps": 5.47, "latency_ms": 400}, "lora_sf12_125k": {"bandwidth_kbps": 0.29, "latency_ms": 1500},
             "wifi_g_2.4ghz": {"bandwidth_kbps": 20000, "latency_ms": 20}, "wifi_ac_5ghz": {"bandwidth_kbps": 100000, "latency_ms": 15},
             "ethernet_100m": {"bandwidth_kbps": 100000, "latency_ms": 5}, "ethernet_1g": {"bandwidth_kbps": 1000000, "latency_ms": 1},
             "cellular_4g_lte": {"bandwidth_kbps": 20000, "latency_ms": 50}, "cellular_5g_mid": {"bandwidth_kbps": 150000, "latency_ms": 20},
             "nb_iot": {"bandwidth_kbps": 60, "latency_ms": 1000},
        }
    async def simulate_transfer(self, data_size_bytes: int, network_type: str) -> dict | None:
        if network_type not in self.bandwidth_profiles: log.error(f"Unknown network type for simulation: {network_type}"); return None
        profile = self.bandwidth_profiles[network_type]; bandwidth_kbps = profile["bandwidth_kbps"]; base_latency_ms = profile["latency_ms"]
        base_latency_s = base_latency_ms / 1000.0; bandwidth_bps = bandwidth_kbps * 1000.0
        if bandwidth_bps <= 0:
            log.warning(f"Bandwidth for {network_type} is zero or negative."); return {"network_type": network_type,"data_size_bytes": data_size_bytes,"base_latency_s": base_latency_s,"transfer_time_s": float('inf'),"jitter_s": 0,"total_time_s": float('inf')}
        transfer_time_s = (data_size_bytes * 8) / bandwidth_bps; jitter_factor = random.uniform(-0.1, 0.1); jitter_s = jitter_factor * (base_latency_s + transfer_time_s)
        total_time_s = max(0, base_latency_s + transfer_time_s + jitter_s)
        return {"network_type": network_type,"data_size_bytes": data_size_bytes,"base_latency_s": base_latency_s,"transfer_time_s": transfer_time_s,"jitter_s": jitter_s,"total_time_s": total_time_s}

async def analyze_bandwidth_performance(packet_data_results):
    # Uses the overall average estimated signed size calculated earlier
    log.info("Analyzing bandwidth performance...")
    if not packet_data_results or "avg_original_size" not in packet_data_results:
        log.error("No valid packet size results available for bandwidth analysis")
        return None
    if THEORETICAL_SIG_SIZE <= 0:
         log.error("Cannot estimate signed size for bandwidth analysis without theoretical signature size.")
         return None

    simulator = BandwidthSimulator()
    network_results = {}
    avg_original_size = packet_data_results.get("avg_original_size", 0)
    # Use the overall average estimated signed size
    avg_signed_size = packet_data_results.get("avg_estimated_signed_size", 0)
    # Fallback if average couldn't be calculated but we have components
    if avg_signed_size == 0 and "avg_num_subpackets" in packet_data_results:
        avg_signed_size = avg_original_size + (packet_data_results["avg_num_subpackets"] * THEORETICAL_SIG_SIZE)

    if avg_signed_size <= 0:
         log.error("Average estimated signed size is zero or negative. Cannot run bandwidth analysis.")
         return None

    log.info(f"Using Avg Original Size: {avg_original_size:.1f} B, Avg Est. Signed Size: {avg_signed_size:.1f} B for simulation")
    # (Rest of the function is the same as before)
    tasks = []
    network_types_to_simulate = list(simulator.bandwidth_profiles.keys())
    async def run_single_network_sim(network_type):
        log.info(f"Simulating {network_type}...")
        original_result = await simulator.simulate_transfer(avg_original_size, network_type)
        signed_result = await simulator.simulate_transfer(avg_signed_size, network_type)
        if original_result and signed_result:
            latency_overhead_s = signed_result["total_time_s"] - original_result["total_time_s"]
            overhead_percent = (latency_overhead_s / original_result["total_time_s"]) * 100 if original_result["total_time_s"] > 1e-9 else 0
            return network_type, {"original": original_result, "signed": signed_result, "latency_overhead_s": latency_overhead_s, "overhead_percent": overhead_percent}
        else: log.error(f"Simulation failed for network type {network_type}"); return network_type, None
    simulation_results = await asyncio.gather(*(run_single_network_sim(nt) for nt in network_types_to_simulate))
    for network_type, result_data in simulation_results:
        if result_data: network_results[network_type] = result_data
    if not network_results: log.error("Bandwidth performance simulation yielded no results."); return None
    log.info("Bandwidth performance analysis complete."); return network_results

# plot_network_performance remains the same as before
def plot_network_performance(network_results):
    if not network_results: log.error("No network results to plot"); return
    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)
    network_types = list(network_results.keys()); original_times, signed_times, overhead_percent = [], [], []
    for nt in network_types: res = network_results[nt]; original_times.append(res["original"]["total_time_s"]); signed_times.append(res["signed"]["total_time_s"]); overhead_percent.append(res["overhead_percent"])
    # Sort by original time for better visualization
    sort_indices = np.argsort(original_times); network_types_sorted = [network_types[i] for i in sort_indices]; original_times_sorted = [original_times[i] for i in sort_indices]
    signed_times_sorted = [signed_times[i] for i in sort_indices]; overhead_percent_sorted = [overhead_percent[i] for i in sort_indices]
    try: # Plot transfer times
        plt.figure(figsize=(max(10, len(network_types)*0.8), 7)); bar_width = 0.35; x = np.arange(len(network_types_sorted))
        plt.bar(x - bar_width/2, original_times_sorted, bar_width, label='Original Packet'); plt.bar(x + bar_width/2, signed_times_sorted, bar_width, label='Signed Packet (Est.)')
        plt.xlabel('Network Type (Sorted by Original Packet Time)'); plt.ylabel('Simulated Transfer Time (seconds)'); plt.title('Simulated Packet Transfer Time by Network Type (Subsystem Model)')
        plt.xticks(x, network_types_sorted, rotation=90, fontsize=8); plt.yscale('log'); plt.legend(); plt.grid(axis='y', linestyle='--', alpha=0.6); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'network_transfer_times.png'); plt.savefig(plot_path); plt.close(); log.info(f"Saved network transfer time plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting network transfer times: {e}")
    try: # Plot overhead percentage
        plt.figure(figsize=(max(10, len(network_types)*0.6), 6)); plt.bar(network_types_sorted, overhead_percent_sorted, color='orange', alpha=0.8)
        plt.xlabel('Network Type (Sorted by Original Packet Time)'); plt.ylabel('Latency Overhead due to Signing (%)'); plt.title('Simulated Network Latency Overhead from PQC Signing (Subsystem Model)')
        plt.xticks(rotation=90, fontsize=8); plt.grid(axis='y', linestyle='--', alpha=0.7); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'network_latency_overhead.png'); plt.savefig(plot_path); plt.close(); log.info(f"Saved network latency overhead plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting network overhead: {e}")


# --- Equations and Prediction (Adapted for Subsystem) ---
def formulate_equations(packet_data_results):
    """Formulates conceptual equations for the Sensor Subsystem model."""
    log.info("Formulating conceptual performance equations...")
    if not packet_data_results or THEORETICAL_SIG_SIZE <= 0: return None

    # Assumed signing times *per subpacket* on different local signer hardware
    # These are illustrative guesses!
    signer_processing_times = {"arduino": 0.15, "raspberrypi": 0.03, "fpga": 0.002}
    avg_num_subs = packet_data_results.get("avg_num_subpackets", 2) # Default if not available
    avg_orig_size = packet_data_results.get("avg_original_size", 500)
    avg_subpacket_size = avg_orig_size / avg_num_subs if avg_num_subs > 0 else avg_orig_size

    gamma_coeff = {} # Signing time per byte (s/byte) on local signer
    if avg_subpacket_size > 0:
         gamma_coeff["arduino"] = signer_processing_times["arduino"] / avg_subpacket_size
         gamma_coeff["raspberrypi"] = signer_processing_times["raspberrypi"] / avg_subpacket_size
         gamma_coeff["fpga"] = signer_processing_times["fpga"] / avg_subpacket_size
    else: # Fallbacks
         gamma_coeff["arduino"] = 3e-4; gamma_coeff["raspberrypi"] = 6e-5; gamma_coeff["fpga"] = 4e-6

    # Controller verification time (total per packet)
    avg_verify_time = packet_data_results.get("controller_verification_latency_stats", {}).get("avg", 0.001)

    # Other illustrative parameters
    t_sensor_coord_base = 0.001 # Base overhead for sensor splitting/gathering (ms)
    t_sensor_coord_per_sub = 0.0005 # Overhead per subpacket handled
    t_local_net_base = 0.0001 # Base latency for local req/res
    t_local_net_per_byte = 8 / (1000 * 1000 * 1000) # Assume 1 Gbps local network (s/byte)

    # Energy estimates (illustrative, for local signers)
    energy_signer_cpu_watt = {"arduino": 0.05, "raspberrypi": 2.5, "fpga": 1.5}
    # Network energy for main link (sensor -> controller)
    energy_main_net_jpb = {"bluetooth": 1e-7, "wifi": 5e-8, "cellular": 2e-7, "low_power_wan": 5e-6}

    equations = {
        "description": "Conceptual equations for PQC signing performance (Sensor Subsystem Model)",
        "packet_expansion": {
            "equation": "S_signed_package = S_original + (N_subpackets * β)",
            "parameters": {"β": THEORETICAL_SIG_SIZE},
            "description": "Model for total package size sent to controller."
        },
        "main_transfer_time": {
            "equation": "T_main_net = BaseLatency_main + ((S_signed_package * 8) / Bandwidth_bps_main)",
            "description": "Transfer time from Sensor Subsystem to Controller."
        },
        "total_latency": {
            # Simplified model: Assume parallel signing, take max signer time + overheads
            "equation": "T_total ≈ T_sensor_coord + T_local_net_roundtrip + T_slowest_signer_sign + T_main_net + T_controller_verify_total",
            "parameters": {
                 "T_sensor_coord_eq": f"≈ {t_sensor_coord_base} + N_subpackets * {t_sensor_coord_per_sub}",
                 "T_local_net_roundtrip_eq": f"≈ 2 * ({t_local_net_base} + (AvgSubpacketSize + AvgSigSize) * {t_local_net_per_byte:.2e})", # Rough round trip estimate
                 "T_signer_sign_eq": "γ_signer * AvgSubpacketSize", # Time for one signer
                 "γ_arduino": gamma_coeff.get("arduino", 3e-4),
                 "γ_raspberrypi": gamma_coeff.get("raspberrypi", 6e-5),
                 "γ_fpga": gamma_coeff.get("fpga", 4e-6),
                 "T_controller_verify_total": avg_verify_time # Use measured average
            },
            "description": "Approx total latency: Sensor Coord + Local Net + Slowest Signer + Main Net + Controller Verify."
        },
         "energy_consumption": { # Harder to model total subsystem energy simply
             "equation": "E_total_subsystem ≈ E_sensor_coord + Σ(E_signer_cpu) + E_main_network_tx",
             "description": "Conceptual subsystem energy (omitting local network energy for simplicity)."
             # Prediction function will calculate specific signer energy based on type
         }
    }
    # Add necessary parameters used by prediction function later
    equations["energy_consumption"]["parameters"] = {
        "P_signer_cpu_arduino": energy_signer_cpu_watt.get("arduino", 0.05),
        "P_signer_cpu_raspberrypi": energy_signer_cpu_watt.get("raspberrypi", 2.5),
        "P_signer_cpu_fpga": energy_signer_cpu_watt.get("fpga", 1.5),
        "ε_main_network_bluetooth": energy_main_net_jpb.get("bluetooth", 1e-7),
        "ε_main_network_wifi": energy_main_net_jpb.get("wifi", 5e-8),
        "ε_main_network_cellular": energy_main_net_jpb.get("cellular", 2e-7),
        "ε_main_network_low_power_wan": energy_main_net_jpb.get("low_power_wan", 5e-6)
    }

    log.info("Conceptual equations formulated.")
    return equations

def predict_performance(equations, packet_size: int, num_subpackets: int, local_signer_type: str, main_network_type: str) -> dict | None:
    """Predicts performance based on subsystem equations."""
    if not equations or THEORETICAL_SIG_SIZE <= 0: log.error("Equations or Sig Size missing."); return None
    try:
        # --- Calculate Sizes ---
        beta = equations["packet_expansion"]["parameters"].get("β", 0)
        signed_package_size = max(packet_size + (num_subpackets * beta), packet_size)
        avg_subpacket_size = packet_size / num_subpackets if num_subpackets > 0 else packet_size

        # --- Calculate Latency Components ---
        # 1. Sensor Coordination (Estimate)
        t_sensor_coord_base = 0.001 # From equations params (or define here)
        t_sensor_coord_per_sub = 0.0005
        sensor_coord_time_s = t_sensor_coord_base + num_subpackets * t_sensor_coord_per_sub

        # 2. Local Network (Estimate - simple round trip for one subpacket/sig)
        t_local_net_base = 0.0001
        t_local_net_per_byte = 8 / (1000 * 1000 * 1000) # Assumes 1Gbps
        local_payload_size = avg_subpacket_size + beta # Data + Sig size
        local_net_roundtrip_s = 2 * (t_local_net_base + (local_payload_size * t_local_net_per_byte))

        # 3. Signer Signing Time (Slowest/Representative Signer)
        gamma_key = f"γ_{local_signer_type.lower()}"
        gamma = equations["total_latency"]["parameters"].get(gamma_key)
        if gamma is None: log.error(f"Unknown local signer type: {local_signer_type}"); return None
        signer_sign_time_s = gamma * avg_subpacket_size

        # 4. Main Network Transfer Time
        simulator = BandwidthSimulator() # Use simulator for network profile lookup
        if main_network_type not in simulator.bandwidth_profiles: log.error(f"Unknown main network type: {main_network_type}"); return None
        network_profile = simulator.bandwidth_profiles[main_network_type]
        base_latency_main_s = network_profile["latency_ms"] / 1000.0
        bandwidth_bps_main = network_profile["bandwidth_kbps"] * 1000.0
        main_transfer_time_s = float('inf')
        if bandwidth_bps_main > 0: main_transfer_time_s = base_latency_main_s + ((signed_package_size * 8) / bandwidth_bps_main)

        # 5. Controller Verify Time (Use Average)
        controller_verify_time_s = equations["total_latency"]["parameters"].get("T_controller_verify_total", 0.001)

        # Total Latency (Approx)
        total_time_s = sensor_coord_time_s + local_net_roundtrip_s + signer_sign_time_s + main_transfer_time_s + controller_verify_time_s

        # --- Calculate Energy Components (Focus on Signers + Main Network TX) ---
        # Energy for ONE signer of the specified type
        power_cpu_key = f"P_signer_cpu_{local_signer_type.lower()}"
        power_cpu_watts = equations["energy_consumption"]["parameters"].get(power_cpu_key)
        if power_cpu_watts is None: log.error(f"Unknown signer type for power: {local_signer_type}"); return None
        energy_one_signer_cpu_joules = power_cpu_watts * signer_sign_time_s
        # Rough total signer energy = num_subpackets * energy_one_signer (assumes similar work)
        total_signer_cpu_energy = num_subpackets * energy_one_signer_cpu_joules

        # Energy for Main Network Transmission from Sensor
        network_energy_key = "ε_main_network_wifi" # Default
        if "ble" in main_network_type or "bluetooth" in main_network_type: network_energy_key = "ε_main_network_bluetooth"
        elif "cellular" in main_network_type or "nb_iot" in main_network_type: network_energy_key = "ε_main_network_cellular"
        elif "lora" in main_network_type or "zigbee" in main_network_type: network_energy_key = "ε_main_network_low_power_wan"
        energy_network_jpb = equations["energy_consumption"]["parameters"].get(network_energy_key)
        if energy_network_jpb is None: log.error(f"Unknown network category for energy/byte: key {network_energy_key}"); return None
        energy_main_network_joules = energy_network_jpb * signed_package_size

        # Total Estimated Energy (Signers + Main TX) - ignoring Sensor CPU coord energy for simplicity
        total_energy_joules = total_signer_cpu_energy + energy_main_network_joules

        return {
            "local_signer_type": local_signer_type, "main_network_type": main_network_type,
            "original_size_bytes": packet_size, "num_subpackets": num_subpackets,
            "signed_package_size_bytes": round(signed_package_size, 1),
            "sensor_coord_time_s": round(sensor_coord_time_s, 6),
            "local_net_time_s": round(local_net_roundtrip_s, 6),
            "signer_sign_time_s": round(signer_sign_time_s, 6),
            "main_transfer_time_s": round(main_transfer_time_s, 6) if main_transfer_time_s != float('inf') else float('inf'),
            "controller_verify_time_s": round(controller_verify_time_s, 6),
            "total_time_s": round(total_time_s, 6) if total_time_s != float('inf') else float('inf'),
            "est_subsystem_energy_joules": round(total_energy_joules, 9) # Renamed
        }
    except Exception as e:
        log.error(f"Error during performance prediction: {e}", exc_info=True)
        return None


# --- Reporting (Adapted for Subsystem) ---
def write_report(packet_data_results, network_results, equations):
    """ Writes analysis report for the Sensor Subsystem model. """
    report_path = os.path.join(OUTPUT_DIR, "pqc_analysis_report_subsystem.md")
    log.info(f"Writing analysis report to {report_path}")

    report_sections = OrderedDict()

    # Section 1: Packet Size & Verification Summary
    sec1_content = ""
    if packet_data_results:
        gen = packet_data_results["packets_generated"]
        att = packet_data_results["packets_verification_attempted"]
        ver = packet_data_results["packets_verified_successfully"]
        fail = packet_data_results["packets_verification_failed"]
        avg_subs = packet_data_results.get('avg_num_subpackets', 'N/A')
        if isinstance(avg_subs, float): avg_subs = f"{avg_subs:.1f}"

        sec1_content += f"* **Packets Generated by Sensor(s)**: {gen}\n"
        sec1_content += f"* **Packets Received & Verification Attempted by Controller**: {att}\n"
        sec1_content += f"* **Packets Verified Successfully (All Sub-Signatures)**: {ver} ({ver/att*100:.1f}% success rate if att > 0 else 'N/A')\n"
        sec1_content += f"* **Packets Failed Verification**: {fail}\n\n"
        sec1_content += f"* **Avg Original Packet Size**: {packet_data_results.get('avg_original_size', 0):.1f} bytes\n"
        sec1_content += f"* **Avg Subpackets per Packet**: {avg_subs}\n"
        if THEORETICAL_SIG_SIZE > 0:
            sec1_content += f"* **Theoretical Signature Size ({PQC_SIG_ALG})**: {THEORETICAL_SIG_SIZE} bytes\n"
            sec1_content += f"* **Avg Estimated Signed Packet Size**: {packet_data_results.get('avg_estimated_signed_size', 0):.1f} bytes\n"
            sec1_content += f"* **Avg Expansion Ratio (Estimated)**: {packet_data_results.get('avg_expansion_ratio', 0):.2f}x\n\n"
            sec1_content += "![Packet Size Comparison](plots/packet_size_comparison.png)\n"
            sec1_content += "![Expansion Ratios](plots/expansion_ratios.png)\n"
            sec1_content += "![Average Composition](plots/average_composition.png)\n\n"
        else:
            sec1_content += "*Cannot calculate estimated sizes/ratios without theoretical signature size.*\n\n"
    else:
        sec1_content += "*No packet data available*\n\n"
    report_sections["1. Packet Size and Verification Summary"] = sec1_content

    # Section 2: Controller Verification Latency
    sec2_content = ""
    if packet_data_results and packet_data_results.get("controller_verification_latency_stats"):
        stats = packet_data_results["controller_verification_latency_stats"]
        if "error" not in stats and stats.get("count",0) > 0:
            sec2_content += f"Analysis of time spent by the controller re-splitting packets and verifying *all* sub-signatures (based on {stats.get('count',0)} successfully verified packets).\n\n"
            sec2_content += f"* **Avg Total Verification Latency**: {stats.get('avg', 0):.6f} s\n"
            sec2_content += f"* **Median Total Verification Latency**: {stats.get('median', 0):.6f} s\n"
            # Add other stats if desired (stdev, min, max)
            sec2_content += "\n![Controller Packet Verification Latency](plots/controller_packet_verification_latency.png)\n\n" # Updated filename
        elif "error" in stats:
             sec2_content += f"*Error calculating verification latency stats: {stats['error']}*\n\n"
        else:
            sec2_content += "*No successful verification timings recorded.*\n\n"
    else:
        sec2_content += "*No controller verification latency data available*\n\n"
    report_sections["2. Controller Verification Latency (Subsystem Model)"] = sec2_content

    # Section 3: Network Performance Analysis (Sensor Subsystem -> Controller)
    sec3_content = ""
    if network_results:
        sec3_content += "Simulated transfer times for average *final package sizes* (original data + N signatures) from Sensor Subsystem to Controller across different main network technologies.\n\n"
        sec3_content += "![Network Transfer Times](plots/network_transfer_times.png)\n"
        sec3_content += "![Network Latency Overhead](plots/network_latency_overhead.png)\n\n"
        sec3_content += "### Transfer Time Comparison (Main Network)\n\n"
        sec3_content += "| Network Type       | Original Packet (s) | Signed Package (Est, s) | Latency Overhead (%) |\n" # Updated label
        sec3_content += "|--------------------|---------------------|-------------------------|----------------------|\n"
        sorted_networks = sorted(network_results.keys(), key=lambda nt: network_results[nt]["original"]["total_time_s"])
        for nt in sorted_networks:
            data = network_results[nt]
            orig_time = data['original']['total_time_s']
            sign_time = data['signed']['total_time_s']
            ovhd_pct = data['overhead_percent']
            sec3_content += f"| {nt:<18} | {orig_time:>19.4f} | {sign_time:>23.4f} | {ovhd_pct:>20.2f} |\n"
        sec3_content += "\n"
    else:
        sec3_content += "*No network performance data available*\n\n"
    report_sections["3. Main Network Performance Analysis (Simulated)"] = sec3_content

    # Section 4: Conceptual Performance Equations
    sec4_content = ""
    if equations:
        sec4_content += "These equations provide a simplified conceptual model for the Sensor Subsystem architecture.\n"
        sec4_content += "**Note:** Coefficients and component times (γ, T_verify, T_coord, T_local_net, P_cpu, ε_network) are derived from simulation averages or are illustrative estimates.\n\n"
        # Add equation summaries here based on formulate_equations output
        sec4_content += "### Packet Size Model\n\n"; sec4_content += f"* **Equation**: `{equations['packet_expansion']['equation']}`\n"; sec4_content += f"* **β (Sig Size)**: {equations['packet_expansion']['parameters']['β']} bytes\n\n"
        sec4_content += "### Main Network Transfer Time Model\n\n"; sec4_content += f"* **Equation**: `{equations['main_transfer_time']['equation']}`\n\n"
        sec4_content += "### Total Latency Model (Approximate)\n\n"; sec4_content += f"* **Equation**: `{equations['total_latency']['equation']}`\n"
        sec4_content += f"* **Sensor Coord Time**: `{equations['total_latency']['parameters']['T_sensor_coord_eq']}`\n"
        sec4_content += f"* **Local Net RTT**: `{equations['total_latency']['parameters']['T_local_net_roundtrip_eq']}`\n"
        sec4_content += f"* **Signer Sign Time**: `{equations['total_latency']['parameters']['T_signer_sign_eq']}`\n"
        # List gamma values
        sec4_content += f"  * γ_arduino: {equations['total_latency']['parameters'].get('γ_arduino', 'N/A'):.2e} s/byte\n"; # ... etc
        sec4_content += f"* **Avg Controller Verify Time**: {equations['total_latency']['parameters']['T_controller_verify_total']:.6f} s\n\n"
        sec4_content += "*Note: This model simplifies parallel execution and network contention.*\n\n"
        # Add Energy Equation Summary if desired
    else:
        sec4_content += "*No performance equations available*\n\n"
    report_sections["4. Conceptual Performance Equations"] = sec4_content

    # Section 5: Sample Performance Predictions
    sec5_content = ""
    if equations:
        sec5_content += "Approximate predictions based on the conceptual equations for specific scenarios.\n\n"
        # Define scenarios using local signer type
        scenarios = [
             {"signer_type": "Arduino", "network": "ble_1m", "packet_size": 200, "splits": 2},
             {"signer_type": "Arduino", "network": "lora_sf12_125k", "packet_size": 100, "splits": 1},
             {"signer_type": "RaspberryPi", "network": "wifi_g_2.4ghz", "packet_size": 500, "splits": 3},
             {"signer_type": "FPGA", "network": "ethernet_100m", "packet_size": 1000, "splits": 4},
             {"signer_type": "RaspberryPi", "network": "cellular_4g_lte", "packet_size": 300, "splits": 2},
             {"signer_type": "Arduino", "network": "nb_iot", "packet_size": 50, "splits": 1}
        ]
        # Need to add more columns for the breakdown
        sec5_content += "| Scenario | Signer Type | Main Network   | Pkt Size | Splits | Signed Pkg| Sign(s)| MainNet(s)| Verify(s)| Total(s)| Energy(J) |\n"
        sec5_content += "|----------|-------------|----------------|----------|--------|-----------|---------|-----------|-----------|----------|-----------|\n"
        for i, sc in enumerate(scenarios):
             pred = predict_performance(equations, sc["packet_size"], sc["splits"], sc["signer_type"], sc["network"])
             if pred:
                  mnet_s = f"{pred['main_transfer_time_s']:.4f}" if pred['main_transfer_time_s'] != float('inf') else "Inf"
                  tot_s = f"{pred['total_time_s']:.4f}" if pred['total_time_s'] != float('inf') else "Inf"
                  nrg_j = f"{pred['est_subsystem_energy_joules']:.6f}" if pred['est_subsystem_energy_joules'] != float('inf') else "Inf"
                  sec5_content += (f"| {i+1:<8} | {pred['local_signer_type']:<11} | {pred['main_network_type']:<14} | "
                                   f"{pred['original_size_bytes']:>8} | {pred['num_subpackets']:>6} | {pred['signed_package_size_bytes']:>9.1f} | "
                                   f"{pred['signer_sign_time_s']:>7.4f} | {mnet_s:>9} | {pred['controller_verify_time_s']:>9.6f} | " # Added verify
                                   f"{tot_s:>8} | {nrg_j:>9} |\n") # Added Energy
             else:
                  sec5_content += f"| {i+1:<8} | {sc['signer_type']:<11} | {sc['network']:<14} | {sc['packet_size']:>8} | {sc['splits']:>6} | - | - | - | - | - | FAILED |\n"
        sec5_content += "*Latency Breakdown (Approx): Total = SensorCoord + LocalNet + SignerSign + MainNet + ControllerVerify*\n"
        sec5_content += "*Energy Estimate = SignerCPU(s) + MainNetTX*\n\n"
    else:
        sec5_content += "*No performance predictions available (equations not formulated)*\n\n"
    report_sections["5. Sample Performance Predictions"] = sec5_content

    # --- Write Report File ---
    with open(report_path, 'w') as f:
        f.write("# PQC Signing Performance Analysis Report (Sensor Subsystem Model)\n\n")
        f.write(f"*Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        f.write(f"*PQC Algorithm: {PQC_SIG_ALG}*\n\n")
        f.write("---\n\n")
        for title, content in report_sections.items():
            f.write(f"## {title}\n\n"); f.write(content); f.write("\n---\n\n")
    log.info("Report generation complete.")


async def main():
    """Main function to run the analysis."""
    log.info("--- Starting PQC Performance Analysis (Sensor Subsystem Model) ---")

    # 1. Analyze Packet Data (Sizes & Verification)
    packet_data_results = analyze_packet_data()
    if packet_data_results:
        if THEORETICAL_SIG_SIZE > 0:
            log.info(f"Avg Expansion Ratio (Est.): {packet_data_results.get('avg_expansion_ratio', 0):.2f}x")
        if packet_data_results.get("controller_verification_latency_stats"):
             log.info(f"Avg Controller Packet Verification Latency: {packet_data_results['controller_verification_latency_stats'].get('avg', 0):.6f}s")
        plot_packet_size_analysis(packet_data_results)
        plot_verification_latency(packet_data_results) # Plot verification latency
    else:
        log.error("Cannot proceed without packet data results."); return

    # 2. Network Performance Simulation
    network_results = await analyze_bandwidth_performance(packet_data_results)
    if network_results:
        plot_network_performance(network_results)
    else:
        log.warning("Skipping equation/report generation due to network analysis errors or missing inputs.")
        # Don't exit entirely, allow report generation with missing sections if needed
        # return

    # 3. Formulate Equations
    equations = formulate_equations(packet_data_results)

    # 4. Write Report
    write_report(packet_data_results, network_results, equations)

    log.info("--- Analysis Complete ---")

if __name__ == "__main__":
    # Add argparser if needed for analyzer config later
    try:
        asyncio.run(main())
    except Exception as e:
        log.exception("An error occurred during analysis:")
