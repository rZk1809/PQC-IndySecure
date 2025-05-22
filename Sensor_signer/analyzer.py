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
    VERIFIED_PACKETS_FILE, # Only verified log needed now
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
    # Note: length_signature depends on the instance being created,
    # might not be available directly as a class property for all algs/wrappers.
    # We might need to generate a dummy signature or find it in docs/spec.
    # Let's assume a way to get it or hardcode based on FIPS 204 spec if needed.
    # From FIPS 204 / search results: ML-DSA-44 sig size = 2420 bytes
    if PQC_SIG_ALG == "ML-DSA-44": THEORETICAL_SIG_SIZE = 2420
    elif PQC_SIG_ALG == "ML-DSA-65": THEORETICAL_SIG_SIZE = 3309
    elif PQC_SIG_ALG == "ML-DSA-87": THEORETICAL_SIG_SIZE = 4627
    else:
        log.warning(f"Could not determine theoretical signature size for {PQC_SIG_ALG}. Size analysis might be limited.")
    log.info(f"Using theoretical signature size for {PQC_SIG_ALG}: {THEORETICAL_SIG_SIZE} bytes")
except Exception as e:
    log.error(f"OQS Init Error: {e}. Cannot determine theoretical signature size.")


# --- Analysis Functions ---

def analyze_packet_data():
    """Analyzes generated packet sizes and verification results."""
    log.info("Analyzing generated packet sizes and verification results...")
    original_packets_data = {} # {packet_id: size}
    verified_results = {} # {packet_id: {"status": str, "verify_latency": float}}
    total_verified = 0
    total_failed = 0
    verification_latencies = []

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
        log.error(f"Error loading generated packets file {GENERATED_PACKETS_FILE}: {e}")
        return None # Cannot proceed without original sizes

    # 2. Load Verified Packets (for status and latency)
    try:
        with open(VERIFIED_PACKETS_FILE, 'r') as f:
            verified_log = json.load(f)
        log.info(f"Loaded {len(verified_log)} verification log entries from {VERIFIED_PACKETS_FILE}")
        for entry in verified_log:
            packet_id = entry.get("packet_id")
            status = entry.get("verification_status")
            latency = entry.get("controller_verification_latency_sec")
            if packet_id and status:
                verified_results[packet_id] = {"status": status, "verify_latency": latency}
                if status == "Success":
                    total_verified += 1
                    if latency is not None:
                        verification_latencies.append(latency)
                else:
                    total_failed += 1
            else:
                 log.warning(f"Skipping invalid verification log entry: {entry}")

    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.warning(f"Could not load verified packets file {VERIFIED_PACKETS_FILE}: {e}. Analysis will be limited.")
        # Allow analysis to proceed with only original data if verification log missing


    # 3. Combine and Calculate Results
    results = {
        "packets_generated": len(original_packets_data),
        "packets_verification_attempted": len(verified_results),
        "packets_verified_successfully": total_verified,
        "packets_verification_failed": total_failed,
        "original_sizes": [],
        "estimated_signed_sizes": [], # Original + Theoretical Sig Size
        "expansion_ratios": [], # Based on theoretical size
        "controller_verification_latencies": verification_latencies,
        "per_packet": {} # Store combined info
    }

    processed_packet_ids = set(verified_results.keys()) & set(original_packets_data.keys())
    results["packets_analyzed_end_to_end"] = len(processed_packet_ids)

    for packet_id in processed_packet_ids:
        original_size = original_packets_data[packet_id]
        verify_info = verified_results[packet_id]
        estimated_signed_size = original_size + THEORETICAL_SIG_SIZE
        expansion_ratio = estimated_signed_size / original_size if original_size > 0 else 0

        results["original_sizes"].append(original_size)
        if verify_info["status"] == "Success": # Only include successful packets in size/ratio stats? debatable
            results["estimated_signed_sizes"].append(estimated_signed_size)
            results["expansion_ratios"].append(expansion_ratio)

        results["per_packet"][packet_id] = {
            "original_size": original_size,
            "estimated_signed_size": estimated_signed_size,
            "expansion_ratio": expansion_ratio,
            "verification_status": verify_info["status"],
            "controller_verify_latency": verify_info["verify_latency"]
        }

    # Calculate overall averages
    if results["original_sizes"]:
        try: results["avg_original_size"] = statistics.mean(results["original_sizes"])
        except: results["avg_original_size"] = 0
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
    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)

    # Data for plotting (only use packets analyzed end-to-end)
    packet_ids = sorted(list(results["per_packet"].keys()))
    original_sizes = [results["per_packet"][pid]["original_size"] for pid in packet_ids]
    estimated_signed_sizes = [results["per_packet"][pid]["estimated_signed_size"] for pid in packet_ids]
    expansion_ratios = [results["per_packet"][pid]["expansion_ratio"] for pid in packet_ids]

    # Plot 1: Original vs Estimated Signed Size
    try:
        plt.figure(figsize=(max(10, len(packet_ids)*0.6), 6))
        bar_width = 0.35; x = np.arange(len(packet_ids))
        plt.bar(x - bar_width/2, original_sizes, bar_width, label='Original Size (Bytes)')
        plt.bar(x + bar_width/2, estimated_signed_sizes, bar_width, label=f'Est. Signed Size (Orig + {THEORETICAL_SIG_SIZE} B Sig)')
        plt.xlabel('Packet ID'); plt.ylabel('Size (bytes)')
        plt.title(f'Packet Size: Original vs Estimated Signed ({PQC_SIG_ALG})')
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
        if "avg_original_size" in results and THEORETICAL_SIG_SIZE > 0:
            plt.figure(figsize=(7, 7))
            avg_original = results["avg_original_size"]
            avg_sig_overhead = THEORETICAL_SIG_SIZE # Simple model: one signature
            if avg_original > 0 or avg_sig_overhead > 0:
                labels = ['Avg Original Data', f'Signature Overhead ({PQC_SIG_ALG})']
                sizes = [avg_original, avg_sig_overhead]
                colors = ['lightblue', 'coral']
                plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
                plt.title(f'Average Composition of Signed Packet\n(Avg Orig: {avg_original:.1f} B, Sig: {avg_sig_overhead} B)')
                plt.tight_layout()
                plot_path = os.path.join(plots_dir, 'average_composition.png'); plt.savefig(plot_path); plt.close()
                log.info(f"Saved average composition plot to {plot_path}")
            else: log.warning("Average sizes are zero, skipping composition pie chart.")
        else: log.warning("Missing average data or signature size for composition pie chart.")
    except Exception as e: log.error(f"Error plotting average composition: {e}")


def plot_verification_latency(results):
    """Plots controller verification latency distribution."""
    if not results or "controller_verification_latency_stats" not in results or results["controller_verification_latency_stats"].get("count", 0) == 0:
        log.warning("No verification latency data to plot.")
        return
    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)
    latencies = results.get("controller_verification_latencies", [])
    stats = results["controller_verification_latency_stats"]

    try:
        plt.figure(figsize=(10, 6))
        plt.hist(latencies, bins=20, alpha=0.75, color='skyblue', edgecolor='black')
        plt.axvline(stats.get("avg", 0), color='red', linestyle='dashed', linewidth=1, label=f'Avg: {stats.get("avg", 0):.6f}s')
        plt.axvline(stats.get("median", 0), color='green', linestyle='dashed', linewidth=1, label=f'Median: {stats.get("median", 0):.6f}s')
        plt.xlabel('Verification Latency (seconds)')
        plt.ylabel('Number of Packets')
        plt.title(f'Controller Signature Verification Latency Distribution ({PQC_SIG_ALG})')
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.6)
        plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'controller_verification_latency.png')
        plt.savefig(plot_path); plt.close(); log.info(f"Saved verification latency plot to {plot_path}")
    except Exception as e:
        log.error(f"Error plotting verification latency histogram: {e}")


# (BandwidthSimulator, analyze_bandwidth_performance, plot_network_performance remain largely the same)
# Just need to ensure analyze_bandwidth_performance uses the new results structure
class BandwidthSimulator:
    # (Keep the class definition from the previous version)
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
        # await asyncio.sleep(total_time_s) # Commented out for faster analysis
        return {"network_type": network_type,"data_size_bytes": data_size_bytes,"base_latency_s": base_latency_s,"transfer_time_s": transfer_time_s,"jitter_s": jitter_s,"total_time_s": total_time_s}

async def analyze_bandwidth_performance(packet_data_results):
    log.info("Analyzing bandwidth performance...")
    if not packet_data_results or "avg_original_size" not in packet_data_results:
        log.error("No valid packet size results available for bandwidth analysis")
        return None

    simulator = BandwidthSimulator()
    network_results = {}
    avg_original_size = packet_data_results.get("avg_original_size", 0)
    # Use the *estimated* signed size from the results
    avg_signed_size = packet_data_results.get("avg_estimated_signed_size", avg_original_size + THEORETICAL_SIG_SIZE)

    log.info(f"Using Avg Original Size: {avg_original_size:.1f} B, Avg Est. Signed Size: {avg_signed_size:.1f} B for simulation")

    tasks = []
    network_types_to_simulate = list(simulator.bandwidth_profiles.keys())

    async def run_single_network_sim(network_type):
        log.info(f"Simulating {network_type}...")
        original_result = await simulator.simulate_transfer(avg_original_size, network_type)
        signed_result = await simulator.simulate_transfer(avg_signed_size, network_type) # Use estimated signed size
        if original_result and signed_result:
            latency_overhead_s = signed_result["total_time_s"] - original_result["total_time_s"]
            overhead_percent = 0
            if original_result["total_time_s"] > 1e-9:
                overhead_percent = (latency_overhead_s / original_result["total_time_s"]) * 100
            return network_type, {"original": original_result, "signed": signed_result, "latency_overhead_s": latency_overhead_s, "overhead_percent": overhead_percent}
        else:
            log.error(f"Simulation failed for network type {network_type}")
            return network_type, None

    simulation_results = await asyncio.gather(*(run_single_network_sim(nt) for nt in network_types_to_simulate))
    for network_type, result_data in simulation_results:
        if result_data:
            network_results[network_type] = result_data

    if not network_results:
        log.error("Bandwidth performance simulation yielded no results.")
        return None

    log.info("Bandwidth performance analysis complete.")
    return network_results

def plot_network_performance(network_results):
    # (Keep the plotting function from the previous version - it should work with the new results structure)
    if not network_results: log.error("No network results to plot"); return
    plots_dir = os.path.join(OUTPUT_DIR, "plots"); os.makedirs(plots_dir, exist_ok=True)
    network_types = list(network_results.keys()); original_times, signed_times, overhead_percent = [], [], []
    for nt in network_types: res = network_results[nt]; original_times.append(res["original"]["total_time_s"]); signed_times.append(res["signed"]["total_time_s"]); overhead_percent.append(res["overhead_percent"])
    sort_indices = np.argsort(original_times); network_types_sorted = [network_types[i] for i in sort_indices]; original_times_sorted = [original_times[i] for i in sort_indices]
    signed_times_sorted = [signed_times[i] for i in sort_indices]; overhead_percent_sorted = [overhead_percent[i] for i in sort_indices]
    try:
        plt.figure(figsize=(max(10, len(network_types)*0.8), 7)); bar_width = 0.35; x = np.arange(len(network_types_sorted))
        plt.bar(x - bar_width/2, original_times_sorted, bar_width, label='Original Packet'); plt.bar(x + bar_width/2, signed_times_sorted, bar_width, label='Signed Packet (Est.)')
        plt.xlabel('Network Type (Sorted by Original Packet Time)'); plt.ylabel('Simulated Transfer Time (seconds)'); plt.title('Simulated Packet Transfer Time by Network Type')
        plt.xticks(x, network_types_sorted, rotation=90, fontsize=8); plt.yscale('log'); plt.legend(); plt.grid(axis='y', linestyle='--', alpha=0.6); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'network_transfer_times.png'); plt.savefig(plot_path); plt.close(); log.info(f"Saved network transfer time plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting network transfer times: {e}")
    try:
        plt.figure(figsize=(max(10, len(network_types)*0.6), 6)); plt.bar(network_types_sorted, overhead_percent_sorted, color='orange', alpha=0.8)
        plt.xlabel('Network Type (Sorted by Original Packet Time)'); plt.ylabel('Latency Overhead due to Signing (%)'); plt.title('Simulated Network Latency Overhead from PQC Signing')
        plt.xticks(rotation=90, fontsize=8); plt.grid(axis='y', linestyle='--', alpha=0.7); plt.tight_layout()
        plot_path = os.path.join(plots_dir, 'network_latency_overhead.png'); plt.savefig(plot_path); plt.close(); log.info(f"Saved network latency overhead plot to {plot_path}")
    except Exception as e: log.error(f"Error plotting network overhead: {e}")


# --- Equations and Prediction (Simplified) ---
def formulate_equations(packet_data_results):
    """Formulates simplified conceptual equations."""
    log.info("Formulating conceptual performance equations...")
    if not packet_data_results: return None

    # Base processing times assumed for signing *at the sensor*
    # These are illustrative - real values depend heavily on implementation and hardware
    base_signing_times = {"arduino": 0.25, "raspberrypi": 0.05, "fpga_accel": 0.005} # Hypothetical times for signing a ~500B packet
    avg_pkt_size = packet_data_results.get("avg_original_size", 500)
    gamma_coeff = {} # Signing time per byte (s/byte)
    if avg_pkt_size > 0:
         gamma_coeff["arduino"] = base_signing_times["arduino"] / avg_pkt_size
         gamma_coeff["raspberrypi"] = base_signing_times["raspberrypi"] / avg_pkt_size
         gamma_coeff["fpga_accel"] = base_signing_times["fpga_accel"] / avg_pkt_size
    else: # Fallbacks
         gamma_coeff["arduino"] = 5e-4; gamma_coeff["raspberrypi"] = 1e-4; gamma_coeff["fpga_accel"] = 1e-5

    # Add verification time (based on simulation results)
    avg_verify_time = packet_data_results.get("controller_verification_latency_stats", {}).get("avg", 0.001) # Default 1ms

    # Energy estimates (illustrative)
    energy_cpu_watt = {"arduino": 0.05, "raspberrypi": 2.5, "fpga_accel": 1.5}
    energy_network_joule_per_byte = {"bluetooth": 1e-7, "wifi": 5e-8, "cellular": 2e-7, "low_power_wan": 5e-6}


    equations = {
        "description": "Conceptual equations for PQC signing performance (Sensor-Signer Model)",
        "packet_expansion": {
            "equation": "S_signed = S_original + β",
            "parameters": {"β": THEORETICAL_SIG_SIZE}, # Single signature overhead
            "description": "Model for total signed data size (original + one signature)."
        },
        "transfer_time": {
            "equation": "T_transfer = BaseLatency + ((S_signed * 8) / Bandwidth_bps)",
            "description": "Transfer time from Sensor-Signer to Controller."
        },
        "total_latency": {
            "equation": "T_total = T_sensor_sign + T_transfer + T_controller_verify",
            "parameters": {
                "T_sensor_sign_equation": "T_sensor_sign = γ * S_original",
                "γ_arduino": gamma_coeff.get("arduino", 5e-4),
                "γ_raspberrypi": gamma_coeff.get("raspberrypi", 1e-4),
                "γ_fpga_accel": gamma_coeff.get("fpga_accel", 1e-5), # FPGA/hardware accel on sensor
                "T_controller_verify": avg_verify_time # Avg verification time at controller
            },
            "description": "Simplified total latency: Sensor Signing + Network + Controller Verification."
        },
        "energy_consumption": {
             "equation": "E_total = E_sensor_sign + E_network = (P_sensor_cpu * T_sensor_sign) + (ε_network_jpb * S_signed)",
             "parameters": {
                 "P_sensor_cpu_arduino": energy_cpu_watt.get("arduino", 0.05),
                 "P_sensor_cpu_raspberrypi": energy_cpu_watt.get("raspberrypi", 2.5),
                 "P_sensor_cpu_fpga_accel": energy_cpu_watt.get("fpga_accel", 1.5),
                 "ε_network_bluetooth": energy_network_joule_per_byte.get("bluetooth", 1e-7),
                 # ... (other network energy params) ...
                 "ε_network_low_power_wan": energy_network_joule_per_byte.get("low_power_wan", 5e-6),
                 "ε_network_bluetooth": energy_network_joule_per_byte.get("bluetooth", 1e-7),
                 "ε_network_wifi": energy_network_joule_per_byte.get("wifi", 5e-8), # Add this line
                 "ε_network_cellular": energy_network_joule_per_byte.get("cellular", 2e-7), # Add this line
                 "ε_network_low_power_wan": energy_network_joule_per_byte.get("low_power_wan", 5e-6)
             
             },
             "description": "Simplified energy consumption model (Joules) - Sensor perspective."
         }
    }
    log.info("Conceptual equations formulated.")
    return equations

def predict_performance(equations, packet_size: int, sensor_device_type: str, network_type: str) -> dict | None:
    """Predicts performance based on simplified equations."""
    if not equations: log.error("Equations dictionary is missing."); return None
    try:
        # Packet Size
        beta = equations["packet_expansion"]["parameters"].get("β", 0)
        signed_size = max(packet_size + beta, packet_size)

        # Sensor Signing Time
        gamma_key = f"γ_{sensor_device_type.lower()}"
        gamma = equations["total_latency"]["parameters"].get(gamma_key)
        if gamma is None: log.error(f"Unknown sensor device type for CPU time: {sensor_device_type}"); return None
        sensor_sign_time_s = gamma * packet_size

        # Network Transfer Time
        simulator = BandwidthSimulator() # Use simulator for network profile lookup
        if network_type not in simulator.bandwidth_profiles: log.error(f"Unknown network type for transfer time: {network_type}"); return None
        network_profile = simulator.bandwidth_profiles[network_type]
        base_latency_s = network_profile["latency_ms"] / 1000.0
        bandwidth_bps = network_profile["bandwidth_kbps"] * 1000.0
        transfer_time_s = float('inf')
        if bandwidth_bps > 0: transfer_time_s = base_latency_s + ((signed_size * 8) / bandwidth_bps)

        # Controller Verify Time
        controller_verify_time_s = equations["total_latency"]["parameters"].get("T_controller_verify", 0.001)

        # Total Latency
        total_time_s = sensor_sign_time_s + transfer_time_s + controller_verify_time_s

        # Energy (Sensor)
        power_cpu_key = f"P_sensor_cpu_{sensor_device_type.lower()}"
        power_cpu_watts = equations["energy_consumption"]["parameters"].get(power_cpu_key)
        if power_cpu_watts is None: log.error(f"Unknown sensor device type for CPU power: {sensor_device_type}"); return None
        energy_cpu_joules = power_cpu_watts * sensor_sign_time_s

        network_energy_key = "ε_network_wifi" # Default
        if "ble" in network_type or "bluetooth" in network_type: network_energy_key = "ε_network_bluetooth"
        elif "cellular" in network_type or "nb_iot" in network_type: network_energy_key = "ε_network_cellular"
        elif "lora" in network_type or "zigbee" in network_type: network_energy_key = "ε_network_low_power_wan"
        energy_network_jpb = equations["energy_consumption"]["parameters"].get(network_energy_key)
        if energy_network_jpb is None: log.error(f"Unknown network category for energy/byte: derived key {network_energy_key} from {network_type}"); return None
        energy_network_joules = energy_network_jpb * signed_size
        total_energy_joules = energy_cpu_joules + energy_network_joules

        return {
            "sensor_device_type": sensor_device_type, "network_type": network_type,
            "original_size_bytes": packet_size, "signed_size_bytes": round(signed_size, 1),
            "sensor_sign_time_s": round(sensor_sign_time_s, 6),
            "transfer_time_s": round(transfer_time_s, 6) if transfer_time_s != float('inf') else float('inf'),
            "controller_verify_time_s": round(controller_verify_time_s, 6),
            "total_time_s": round(total_time_s, 6) if total_time_s != float('inf') else float('inf'),
            "sensor_energy_consumption_joules": round(total_energy_joules, 9)
        }
    except Exception as e:
        log.error(f"Error during performance prediction: {e}", exc_info=True)
        return None


# --- Reporting (Simplified) ---
def write_report(packet_data_results, network_results, equations):
    """ Writes an analysis report to a Markdown file (adapted for sensor-signer model). """
    report_path = os.path.join(OUTPUT_DIR, "pqc_analysis_report_sensor_signer.md")
    log.info(f"Writing analysis report to {report_path}")

    report_sections = OrderedDict()

    # Section 1: Packet Size & Verification Summary
    sec1_content = ""
    if packet_data_results:
        gen = packet_data_results["packets_generated"]
        att = packet_data_results["packets_verification_attempted"]
        ver = packet_data_results["packets_verified_successfully"]
        fail = packet_data_results["packets_verification_failed"]
        sec1_content += f"* **Packets Generated by Sensor(s)**: {gen}\n"
        sec1_content += f"* **Packets Received & Verification Attempted by Controller**: {att}\n"
        sec1_content += f"* **Packets Verified Successfully**: {ver} ({ver/att*100:.1f}% success rate)\n"
        sec1_content += f"* **Packets Failed Verification**: {fail}\n\n"
        sec1_content += f"* **Avg Original Packet Size**: {packet_data_results.get('avg_original_size', 0):.1f} bytes\n"
        sec1_content += f"* **Theoretical Signature Size ({PQC_SIG_ALG})**: {THEORETICAL_SIG_SIZE} bytes\n"
        sec1_content += f"* **Avg Estimated Signed Packet Size**: {packet_data_results.get('avg_estimated_signed_size', 0):.1f} bytes\n"
        sec1_content += f"* **Avg Expansion Ratio (Estimated)**: {packet_data_results.get('avg_expansion_ratio', 0):.2f}x\n\n"
        sec1_content += "![Packet Size Comparison](plots/packet_size_comparison.png)\n"
        sec1_content += "![Expansion Ratios](plots/expansion_ratios.png)\n"
        sec1_content += "![Average Composition](plots/average_composition.png)\n\n"
    else:
        sec1_content += "*No packet size data available*\n\n"
    report_sections["1. Packet Size and Verification Summary"] = sec1_content

    # Section 2: Controller Verification Latency
    sec2_content = ""
    if packet_data_results and packet_data_results.get("controller_verification_latency_stats"):
        stats = packet_data_results["controller_verification_latency_stats"]
        if "error" not in stats:
            sec2_content += f"Analysis of time spent purely on signature verification within the controller (based on {stats.get('count',0)} successfully verified packets).\n\n"
            sec2_content += f"* **Avg Verification Latency**: {stats.get('avg', 0):.6f} s\n"
            sec2_content += f"* **Median Verification Latency**: {stats.get('median', 0):.6f} s\n"
            sec2_content += f"* **Std Dev**: {stats.get('stdev', 0):.6f} s\n"
            sec2_content += f"* **Min / Max**: {stats.get('min', 0):.6f} s / {stats.get('max', 0):.6f} s\n\n"
            sec2_content += "![Controller Verification Latency](plots/controller_verification_latency.png)\n\n"
        else:
             sec2_content += f"*Error calculating verification latency stats: {stats['error']}*\n\n"
    else:
        sec2_content += "*No controller verification latency data available*\n\n"
    report_sections["2. Controller Verification Latency (Simulation)"] = sec2_content


    # Section 3: Network Performance (Largely same as before)
    sec3_content = ""
    if network_results:
        sec3_content += "Simulated transfer times for average packet sizes across different network technologies (Sensor-Signer to Controller).\n\n"
        sec3_content += "![Network Transfer Times](plots/network_transfer_times.png)\n"
        sec3_content += "![Network Latency Overhead](plots/network_latency_overhead.png)\n\n"
        sec3_content += "### Transfer Time Comparison\n\n"
        sec3_content += "| Network Type       | Original Packet (s) | Signed Packet (Est, s) | Latency Overhead (%) |\n"
        sec3_content += "|--------------------|---------------------|------------------------|----------------------|\n"
        sorted_networks = sorted(network_results.keys(), key=lambda nt: network_results[nt]["original"]["total_time_s"])
        for nt in sorted_networks:
            data = network_results[nt]
            orig_time = data['original']['total_time_s']
            sign_time = data['signed']['total_time_s']
            ovhd_pct = data['overhead_percent']
            sec3_content += f"| {nt:<18} | {orig_time:>19.4f} | {sign_time:>22.4f} | {ovhd_pct:>20.2f} |\n"
        sec3_content += "\n"
    else:
        sec3_content += "*No network performance data available*\n\n"
    report_sections["3. Network Performance Analysis (Simulated)"] = sec3_content


    # Section 4: Conceptual Performance Equations (Simplified)
    sec4_content = ""
    if equations:
        sec4_content += "These equations provide a simplified conceptual model for performance estimation in the Sensor-Signer architecture.\n"
        sec4_content += "**Note:** Coefficients (β, γ, T_verify, P_cpu, ε_network) are derived from simulation averages or are illustrative placeholders.\n\n"
        # Add equation summaries here based on the structure in formulate_equations
        sec4_content += "### Packet Size Model\n\n"
        sec4_content += f"* **Equation**: `{equations['packet_expansion']['equation']}`\n"
        sec4_content += f"* **β (Sig Size)**: {equations['packet_expansion']['parameters']['β']} bytes\n\n"
        sec4_content += "### Network Transfer Time Model\n\n"
        sec4_content += f"* **Equation**: `{equations['transfer_time']['equation']}`\n\n"
        sec4_content += "### Total Latency Model (Sensor Sign + Network + Controller Verify)\n\n"
        sec4_content += f"* **Equation**: `{equations['total_latency']['equation']}`\n"
        sec4_content += f"* **Sensor Sign Time**: `{equations['total_latency']['parameters']['T_sensor_sign_equation']}`\n"
        # List gamma values
        sec4_content += f"  * γ_arduino: {equations['total_latency']['parameters'].get('γ_arduino', 'N/A'):.2e} s/byte\n"
        sec4_content += f"  * γ_raspberrypi: {equations['total_latency']['parameters'].get('γ_raspberrypi', 'N/A'):.2e} s/byte\n"
        sec4_content += f"  * γ_fpga_accel: {equations['total_latency']['parameters'].get('γ_fpga_accel', 'N/A'):.2e} s/byte\n"
        sec4_content += f"* **Avg Controller Verify Time**: {equations['total_latency']['parameters']['T_controller_verify']:.6f} s\n\n"
        sec4_content += "### Sensor Energy Consumption Model\n\n"
        sec4_content += f"* **Equation**: `{equations['energy_consumption']['equation']}`\n"
        # List power and network energy values
        # ... (omitted for brevity, but add P_cpu and ε_network params here) ...
        sec4_content += "\n"
    else:
        sec4_content += "*No performance equations available*\n\n"
    report_sections["4. Conceptual Performance Equations"] = sec4_content


    # Section 5: Sample Performance Predictions (Simplified)
    sec5_content = ""
    if equations:
        sec5_content += "Predictions based on the conceptual equations for specific Sensor-Signer scenarios.\n\n"
        # Define scenarios using sensor types
        scenarios = [
             {"sensor_type": "Arduino", "network": "ble_1m", "packet_size": 200},
             {"sensor_type": "Arduino", "network": "lora_sf12_125k", "packet_size": 100},
             {"sensor_type": "RaspberryPi", "network": "wifi_g_2.4ghz", "packet_size": 500},
             {"sensor_type": "FPGA_Accel", "network": "ethernet_100m", "packet_size": 1000},
             {"sensor_type": "RaspberryPi", "network": "cellular_4g_lte", "packet_size": 300},
             {"sensor_type": "Arduino", "network": "nb_iot", "packet_size": 50}
        ]
        sec5_content += "| Scenario | Sensor Type | Network          | Pkt Size (B) | Signed (B) | Sign (s)| Net (s) | Verify (s)| Total (s)| Energy (J) |\n"
        sec5_content += "|----------|-------------|------------------|--------------|------------|---------|---------|-----------|----------|------------|\n"
        for i, scenario in enumerate(scenarios):
             prediction = predict_performance(equations, scenario["packet_size"], scenario["sensor_type"], scenario["network"])
             if prediction:
                  net_time_str = f"{prediction['transfer_time_s']:.4f}" if prediction['transfer_time_s'] != float('inf') else "Inf"
                  tot_time_str = f"{prediction['total_time_s']:.4f}" if prediction['total_time_s'] != float('inf') else "Inf"
                  nrg_str = f"{prediction['sensor_energy_consumption_joules']:.6f}" if prediction['sensor_energy_consumption_joules'] != float('inf') else "Inf"
                  sec5_content += (f"| {i+1:<8} | {prediction['sensor_device_type']:<11} | {prediction['network_type']:<16} | "
                                   f"{prediction['original_size_bytes']:>12} | {prediction['signed_size_bytes']:>10.1f} | "
                                   f"{prediction['sensor_sign_time_s']:>7.4f} | {net_time_str:>7} | {prediction['controller_verify_time_s']:>9.6f} | "
                                   f"{tot_time_str:>8} | {nrg_str:>10} |\n")
             else:
                  sec5_content += f"| {i+1:<8} | {scenario['sensor_type']:<11} | {scenario['network']:<16} | {scenario['packet_size']:>12} | - | - | - | - | - | FAILED |\n"
        sec5_content += "\n"
    else:
        sec5_content += "*No performance predictions available (equations not formulated)*\n\n"
    report_sections["5. Sample Performance Predictions"] = sec5_content

    # --- Write Report File ---
    with open(report_path, 'w') as f:
        f.write("# PQC Signing Performance Analysis Report (Sensor-Signer Model)\n\n")
        f.write(f"*Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        f.write(f"*PQC Algorithm: {PQC_SIG_ALG}*\n\n")
        f.write("---\n\n")
        for title, content in report_sections.items():
            f.write(f"## {title}\n\n")
            f.write(content)
            f.write("\n---\n\n")
    log.info("Report generation complete.")


async def main():
    """Main function to run the analysis."""
    log.info("--- Starting PQC Performance Analysis (Sensor-Signer Model) ---")

    # 1. Analyze Packet Data (Sizes & Verification)
    packet_data_results = analyze_packet_data()
    if packet_data_results:
        log.info(f"Avg Expansion Ratio (Est.): {packet_data_results.get('avg_expansion_ratio', 0):.2f}x")
        if packet_data_results.get("controller_verification_latency_stats"):
             log.info(f"Avg Controller Verification Latency: {packet_data_results['controller_verification_latency_stats'].get('avg', 0):.6f}s")
        plot_packet_size_analysis(packet_data_results)
        plot_verification_latency(packet_data_results) # Plot new latency graph
    else:
        log.error("Cannot proceed without packet data results."); return

    # 2. Network Performance Simulation
    network_results = await analyze_bandwidth_performance(packet_data_results)
    if network_results:
        plot_network_performance(network_results)
    else:
        log.error("Skipping equation/report generation due to network analysis errors."); return

    # 3. Formulate Equations
    equations = formulate_equations(packet_data_results)

    # 4. Write Report
    write_report(packet_data_results, network_results, equations)

    log.info("--- Analysis Complete ---")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        log.exception("An error occurred during analysis:")
