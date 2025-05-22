# Performance Analysis of Post-Quantum Signatures (ML-DSA-44) for Securing Distributed Industrial Data

This repository contains the analysis and findings from a study on the performance of ML-DSA-44, a Post-Quantum Cryptography (PQC) signature algorithm, for securing data in distributed industrial settings, particularly focusing on a vehicle assembly line scenario[cite: 1].

## Table of Contents

- [The Problem: The Quantum Threat to Industrial Data](#the-problem-the-quantum-threat-to-industrial-data)
- [The Proposed Solution: ML-DSA-44](#the-proposed-solution-ml-dsa-44)
- [System Architectures Explored](#system-architectures-explored)
  - [Architecture 1: Centralized Orchestration](#architecture-1-centralized-orchestration)
  - [Architecture 2: Sensor-as-Signer (Direct Signing)](#architecture-2-sensor-as-signer-direct-signing)
  - [Architecture 3: Sensor Subsystem (Refined Model)](#architecture-3-sensor-subsystem-refined-model)
- [Simulation and Methodology](#simulation-and-methodology)
- [Key Performance Insights](#key-performance-insights)
  - [Packet Size and Signature Overhead](#packet-size-and-signature-overhead)
  - [Network Latency Impact](#network-latency-impact)
  - [Signature Verification Latency](#signature-verification-latency)
- [Core Findings and Discussion](#core-findings-and-discussion)
- [Conclusion](#conclusion)

## The Problem: The Quantum Threat to Industrial Data

Industrial systems, such as vehicle assembly lines, generate critical data essential for safety, quality control, and regulatory compliance[cite: 2]. Ensuring the authenticity and integrity of this data is paramount for operational trust[cite: 3]. However, the advent of powerful quantum computers threatens to break classical public-key cryptography (like RSA and ECDSA) using algorithms such as Shor's Algorithm, rendering existing digital signatures insecure[cite: 4].

## The Proposed Solution: ML-DSA-44

To counter the quantum threat, Post-Quantum Cryptography (PQC) offers new cryptographic algorithms resistant to attacks from both classical and quantum computers. This project focuses on **ML-DSA-44 (Module-Lattice-based Digital Signature Algorithm)**, which is based on the CRYSTALS-Dilithium scheme. ML-DSA-44 has been standardized by NIST (FIPS 204) and targets a security level comparable to AES-128[cite: 5].

The fundamental operations are:
* **ML-DSA.Sign**: Uses a Private Key, the Message, and an optional Context String to produce a Signature.
* **ML-DSA.Verify**: Uses a Public Key, the Message, the Signature, and an optional Context String to determine if the signature is Valid or Invalid.
    *(As depicted on Page 1 of the presentation)*

## System Architectures Explored

The study investigated three distinct architectures for integrating PQC signing into an industrial workflow:

### Architecture 1: Centralized Orchestration

* **Process**: Sensors transmit unsigned data to a central controller. This controller then delegates signing tasks to dedicated external signer devices and subsequently gathers these signatures for verification[cite: 6].
* **Advantages**: Allows the use of sensors with limited computational power and leverages powerful, dedicated hardware for signing[cite: 7].
* **Critical Flaws**:
    * Transmitting unsigned data from sensor to controller makes it vulnerable to tampering[cite: 8].
    * The central controller becomes a single point of failure and a complex bottleneck[cite: 9].
    *(Diagram on Page 3)*

### Architecture 2: Sensor-as-Signer (Direct Signing)

* **Process**: Sensors locally sign the entire data packet immediately upon its generation, ensuring data integrity *before* any transmission[cite: 10]. The main controller then verifies the received signed packets[cite: 10].
* **Benefits**:
    * Tampering during channel transmission becomes detectable[cite: 11].
    * Simplifies the controller's verification logic and potentially reduces network traffic by avoiding multi-step coordination[cite: 11].
* **Limitations**: Requires sensors to possess substantial computational power to perform ML-DSA signing operations locally[cite: 12].
    *(Sequence Diagram on Page 4)*

### Architecture 3: Sensor Subsystem (Refined Model)

* **Process**: The sensor device coordinates with local, trusted signer units (e.g., Raspberry Pi or FPGA-based accelerators) over a secure wired network. This distributes the signing load before the authenticated data is sent to the main controller[cite: 14].
* **Advantages**:
    * Protects data integrity within the local subsystem[cite: 15].
    * Offloads the computational burden of signing from the primary sensor core[cite: 15].
    * Leverages secure wired connections for robust communication within the subsystem[cite: 16].
* **Challenges**: Introduces increased system complexity for sensor coordination and requires additional infrastructure for the subsystem[cite: 17].

**Note**: Architectures 2 or 3 were implemented in the simulation code for detailed performance analysis[cite: 17].

## Simulation and Methodology

* **Core Technologies**: The simulation was developed using Python 3, leveraging the `asyncio` library for asynchronous operations and the `pyca-oqs` library for the ML-DSA-44 algorithm implementation[cite: 18].
* **Simulated Components**:
    * **Sensor**: Generates data and performs signing (Arch 2) or coordinates local signers (Arch 3)[cite: 19].
    * **Controller**: Verifies incoming signatures and logs the results[cite: 19].
    * **Local Signers**: Operate in Architecture 3 to provide distributed signing capabilities[cite: 20].
* **Network Simulation**: The model incorporated bandwidth constraints and latency to reflect realistic IoT communication delays. Custom scripts were used to analyze logs from these simulations[cite: 21].

## Key Performance Insights

### Packet Size and Signature Overhead

* **Signature Size**: Each ML-DSA-44 signature adds a fixed **2420 bytes** to the data packet[cite: 23].
* **Impact**: This overhead significantly inflates the total packet size, especially for applications where the original sensor data is small (e.g., 50-900 bytes)[cite: 23, 24].
* **Expansion Ratio**: In some simulated cases, the overall packet size expansion ratio approached approximately **4.8x**[cite: 26].
    * The pie chart on Page 7 shows that the signature can constitute around 77.3% of the signed packet when the original data is 712.2 bytes[cite: 22].
    *(Charts on Page 7 illustrate this overhead)*

### Network Latency Impact

* **Increased Transmission Times**: The larger packet sizes resulting from PQC signatures lead to significantly increased data transmission times, particularly over constrained network types such as LoRa and NB-IoT[cite: 29].
* **Latency Increase**: Latency increases due to PQC signing sometimes exceeded **1000%** on these networks[cite: 29].
    *(Bar charts on Pages 8 and 9 show simulated network latency overhead and packet transfer times by network type)*

### Signature Verification Latency

* **Efficiency**: Controller-side signature verification using ML-DSA-44 proved to be highly efficient.
* **Average Time**: The average verification latency was approximately **0.000128 seconds (0.13 ms)** per packet, with a median of 0.000124 seconds[cite: 29]. This affirms the fast computational performance of ML-DSA-44 verification on typical hardware.
    *(Histogram on Page 8 shows the distribution of verification latencies)*

## Core Findings and Discussion

1.  **Security Imperative**: Signing data at its source (as in Architectures 2 or 3) is crucial to prevent undetected data tampering. The centralized baseline architecture (Architecture 1) is insecure due to the transmission of unsigned data[cite: 30, 8].
2.  **Overhead Considerations**: The substantial **2.4 KB overhead per signature** necessitates careful architectural optimization to mitigate the impact on network load and latency[cite: 31].
3.  **Hardware & Network Trade-offs**: While ML-DSA-44 verification is efficient, the signing operation is computationally more demanding. Furthermore, network bandwidth often becomes the primary constraint on overall system latency, more so than the computational aspects of PQC on capable hardware[cite: 32].
4.  **Architecture Suitability**: The choice between the Sensor-as-Signer (Architecture 2) and Sensor Subsystem (Architecture 3) models depends heavily on the computational capabilities of the sensor devices and the scalability requirements of the industrial application[cite: 33].

## Conclusion

The transition to Post-Quantum Cryptography like ML-DSA-44 is vital for securing industrial data against future quantum threats. While ML-DSA-44 offers strong security and efficient verification, its significant signature size poses challenges for network-constrained IoT environments. This study underscores the importance of source-level signing and careful architectural design to balance security needs with performance limitations in practical industrial deployments.

---

*This README is based on the presentation "Performance Analysis of Post-Quantum Signatures (ML-DSA-44) for Securing Distributed Industrial Data" by Rohith Ganesh Kanchi and S.D Madhumitha.*
