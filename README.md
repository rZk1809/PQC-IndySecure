# Performance Analysis of Post-Quantum Signatures (ML-DSA-44) for Securing Distributed Industrial Data

This repository contains the analysis and findings from a study on the performance of ML-DSA-44, a Post-Quantum Cryptography (PQC) signature algorithm, for securing data in distributed industrial settings. The study particularly focuses on a vehicle assembly line scenario to provide a practical context.

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

---

## The Problem: The Quantum Threat to Industrial Data

Industrial systems, such as those found in vehicle assembly lines, generate vast amounts of critical data. This data is essential for maintaining safety standards, ensuring quality control, and meeting regulatory compliance requirements. Therefore, guaranteeing the authenticity and integrity of this industrial data is vital for establishing and maintaining operational trust.

However, a significant challenge is emerging with the development of powerful quantum computers. These machines, leveraging algorithms like Shor's Algorithm, pose a credible threat to classical public-key cryptography systems, including widely used algorithms like RSA and ECDSA. If these classical systems are broken, the digital signatures they produce will no longer be secure, leaving industrial data vulnerable.

---

## The Proposed Solution: ML-DSA-44

To address the threat posed by quantum computers, the field of Post-Quantum Cryptography (PQC) is developing new cryptographic algorithms designed to be resistant to attacks from both classical and quantum computers. This project specifically focuses on **ML-DSA-44 (Module-Lattice-based Digital Signature Algorithm)**.

ML-DSA-44 is based on the CRYSTALS-Dilithium signature scheme, a leading candidate in PQC. It has been standardized by the National Institute of Standards and Technology (NIST) under FIPS 204. The algorithm aims to provide a security level comparable to that of AES-128.

The core operations of ML-DSA are:

* **ML-DSA.Sign**: This operation takes a **Private Key**, the **Message** to be signed, and an optional **Context String** as input. It then produces a digital **Signature**.
* **ML-DSA.Verify**: This operation takes the corresponding **Public Key**, the original **Message**, the **Signature**, and the optional **Context String**. It outputs whether the signature is **Valid** or **Invalid**.

(These operations are visually depicted on Page 1 of the source presentation.)

---

## System Architectures Explored

The study investigated three distinct architectural models for integrating ML-DSA-44 signing into an industrial data workflow. Each architecture presents different trade-offs in terms of security, performance, and complexity.

### Architecture 1: Centralized Orchestration

* **Process Workflow**: In this model, sensors collect data and send this **unsigned data** to a central controller (e.g., a laptop). This controller then delegates the signing tasks to external, potentially more powerful, signer devices. After the data is signed, the signatures are gathered by the controller for verification.
    (A diagram of this architecture is available on Page 3 of the source presentation.)
* **Advantages**:
    * Enables the use of sensors that have limited computational capabilities, as they don't perform the signing themselves.
    * Allows for the utilization of dedicated, powerful hardware for the computationally intensive signing operations.
* **Critical Flaws**:
    * A major vulnerability is that **unsigned data is transmitted** between the sensor and the controller, making it susceptible to tampering before it can be secured with a signature.
    * The central controller acts as a **single complex bottleneck point**, which can impact performance and reliability. If the controller fails, the entire signing and verification process halts.

### Architecture 2: Sensor-as-Signer (Direct Signing)

* **Secure-by-Design at Data Origin**: This architecture takes a "secure-by-design" approach. Sensors locally sign the entire data packets immediately upon generation, ensuring data integrity *before* any transmission over the network. The main controller then receives these already-signed packets and performs verification.
    (A sequence diagram illustrating this process is on Page 4 of the source presentation.)
* **Benefits**:
    * Any tampering with the data during its transmission through the communication channel becomes detectable by the verifier.
    * The controller's logic for verification is simplified, and there's potentially less network traffic as coordination steps for external signing are eliminated.
* **Limitations**:
    * This model **requires sensors to have substantial computational power** to perform the ML-DSA signing operations locally, which might not be feasible for all types of low-cost or resource-constrained sensors.

### Architecture 3: Sensor Subsystem (Refined Model)

* **Design Concept**: This model proposes a sensor that coordinates with local, trusted signer units (e.g., a Raspberry Pi or an FPGA crypto accelerator) over a secure, typically wired, network. The sensor distributes the signing load to these units before sending the fully authenticated data to the main factory network controller.
* **Advantages**:
    * Protects data integrity within the local subsystem, as data is signed before leaving this trusted zone.
    * Offloads the computational burden of signing from the sensor's core processor, allowing the sensor to focus on its primary tasks.
    * Leverages secure wired connections for communication within the subsystem, which are generally more reliable and less prone to interference than wireless connections.
* **Challenges**:
    * This approach **increases system complexity** due to the need for sensor coordination and the additional infrastructure required for the local signer subsystem.

**Implementation Note**: For the performance analysis conducted in this study, either Architecture 2 (Sensor-as-Signer) or Architecture 3 (Sensor Subsystem) was implemented in the simulation code, as these provide on-device or near-device signing capabilities.

---

## Simulation and Methodology

The performance analysis of ML-DSA-44 was conducted using a custom simulation environment.

* **Core Technologies**:
    * The simulation was primarily developed in **Python 3**.
    * The `asyncio` library was used for managing asynchronous operations, crucial for simulating concurrent network activities and sensor operations.
    * The **`pyca-oqs` library** provided the implementation of the ML-DSA-44 algorithm. This library is an integration of the Open Quantum Safe (OQS) project with the Python Cryptographic Authority (pyca) cryptography library.
* **Simulated Components**:
    * **Sensor**: This component was responsible for generating data. Depending on the architecture being simulated (Architecture 2 or 3), it either performed the signing operation itself or coordinated with local signers.
    * **Controller**: This component acted as the verifier. It received signed data packets, performed signature verification, and logged the results.
    * **Local Signers**: These components were active in simulations of Architecture 3, performing the signing operations as directed by the sensor.
* **Network Simulation**:
    * The simulation model incorporated **bandwidth constraints and latency** to reflect realistic conditions found in IoT communication networks. This allowed for an assessment of how PQC signatures perform under various network conditions, from high-bandwidth Ethernet to constrained LoRa or NB-IoT networks.
    * Logs generated from the simulations were then analyzed using custom scripts to extract performance metrics.

---

## Key Performance Insights

The simulations yielded several key insights into the performance characteristics of ML-DSA-44 in an industrial context.

### Packet Size and Signature Overhead

* **PQC Signature Impact**: A significant finding is the size of the ML-DSA-44 signatures. Each signature adds a fixed **2420 bytes** to the data packet.
* **Packet Inflation**: This signature overhead can **significantly inflate the total packet sizes**, especially when the original sensor data packets are small (e.g., payloads ranging from 50 to 900 bytes).
    * For instance, with an average original data size of 712.2 bytes, the 2420-byte signature constitutes approximately **77.3%** of the total signed packet. (This is illustrated in a pie chart on Page 7 of the source presentation).
* **Overall Expansion**: The overall packet size expansion ratio, due to the addition of the signature, was observed to approach approximately **4.8 times** the original size in some cases.
    (A bar chart on Page 7 of the source presentation, titled "Packet Size: Original vs Estimated Signed (ML-DSA-44)," visually demonstrates this for various packet IDs.)

### Network Latency Impact

* **Increased Transmission Times**: The substantial increase in packet sizes due to PQC signatures directly leads to **significantly longer transmission times**. This effect is particularly pronounced when data is sent over **constrained networks** such as LoRa (Long Range) and NB-IoT (Narrowband Internet of Things), which have limited bandwidth.
* **Latency Increase Percentage**: In simulations involving these constrained networks, the latency increase caused by the larger PQC packets sometimes **exceeded 1000%** compared to transmitting the original, unsigned (and thus smaller) packets.
    (A bar chart on Page 8, "Simulated Network Latency Overhead from PQC Signing," and another on Page 9, "Simulated Packet Transfer Time by Network Type," illustrate these impacts across different network types.)

### Signature Verification Latency

* **Verification Efficiency**: Despite the large signature sizes, the controller-side signature verification process for ML-DSA-44 proved to be **highly efficient**.
* **Average Verification Time**: The simulations showed an average verification latency of approximately **0.000128 seconds (which is 0.13 milliseconds)** per packet. The median verification latency was even slightly lower at 0.000124 seconds.
* **Computational Performance**: This affirms the fast computational performance of ML-DSA-44 for signature verification when run on typical hardware (like that of the simulated controller).
    (A histogram on Page 8, "Controller Signature Verification Latency Distribution (ML-DSA-44)," displays the distribution of these verification times.)

---

## Core Findings and Discussion

The performance analysis leads to several important conclusions and discussion points:

1.  **Security Imperative of Source Signing**:
    The study strongly indicates that signing data at its origin (as implemented in Architecture 2 or 3) is essential to prevent undetected data tampering. The centralized baseline architecture (Architecture 1), which transmits unsigned data from sensors, is inherently vulnerable and thus disproven as a secure model for these applications.

2.  **Overhead Considerations and Optimization**:
    The substantial **2.4 KB overhead per signature** is a major factor. This demands careful architectural optimization to mitigate the impact on network load and overall system latency, especially in environments with many sensors or limited bandwidth.

3.  **Hardware & Network Trade-offs**:
    While ML-DSA-44 signature verification is computationally efficient, the signing operation itself is more computationally intensive. However, the study suggests that **network bandwidth often becomes the primary constraint** on overall system latency, potentially more so than the computational time for PQC operations on reasonably capable hardware.

4.  **Architecture Suitability**:
    The decision between deploying a Sensor-as-Signer model (Architecture 2) or a Sensor Subsystem model (Architecture 3) depends heavily on the **specific capabilities of the sensor devices** (processing power, memory) and the **scalability requirements** of the particular industrial application.

---

## Conclusion

The transition to Post-Quantum Cryptography, utilizing algorithms like ML-DSA-44, is becoming vital for securing distributed industrial data against the emerging threat of quantum computers. ML-DSA-44 offers strong, quantum-resistant security and demonstrates efficient signature verification.

However, its significant signature size introduces considerable overhead, which poses challenges for network-constrained IoT environments common in industrial settings. This study underscores the critical importance of implementing signing mechanisms at the data source to ensure integrity. Furthermore, it highlights the need for careful architectural design to balance the robust security needs with the practical performance limitations and resource constraints of industrial deployments.

---

*An insightful project for the future implementations of PQC by Rohith Ganesh Kanchi and S.D Madhumitha.*
