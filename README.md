# Tracking Malicious Flows in Kathara using eBPF

**Authors:**  
- Leonardo Crozzoli (ID 576633)  
- Lorenzo Benzi (ID 578295)

**Advisor:**  
- Tommaso Caiazzi (Kathara Team)

## Introduction

In this repository, you will find a collection of directories and files related to our thesis research. The primary goal of the project is to experiment with advanced techniques for tracking malicious flows within the [Kathara](https://github.com/KatharaFramework/Kathara) network emulation environment using **eBPF** programs.

In the field of cybersecurity, monitoring network traffic flows is essential to detect anomalous and potentially harmful activities.  
Early interception of a cyber attack can greatly reduce its impact on systems and network infrastructure.

## What is Kathara?

**Kathara** is a network emulation framework that allows for the rapid and flexible creation and testing of complex topologies. Based on Linux containers, Kathara makes it possible to configure routers, switches, hosts, and various services in a modular way. With this environment, we can simulate realistic network scenarios and evaluate the behavior of protocols, security solutions, and monitoring systems without the need for costly physical infrastructure.

## What is a DDoS Attack?

A **DDoS (Distributed Denial of Service)** attack is a type of cyber assault in which multiple malicious sources send an enormous volume of requests to a specific target (a server, an online service, a website) to overload it and prevent normal operation. A DDoS attack obstructs legitimate users from accessing network resources, causing financial and reputational damage.

## What are eBPF Programs?

**eBPF (Extended Berkeley Packet Filter)** is a technology integrated into the Linux kernel that allows for analyzing, filtering, and modifying network traffic “on the fly.” Unlike traditional systems, eBPF enables the insertion of small programs directly into the kernel without the need to recompile it or use external modules. These programs stand out for their:

- **Efficiency:** Operate close to the system core, reducing latency and overhead.  
- **Flexibility:** Can be updated on the fly, allowing dynamic evolution of filtering logic.  
- **Security:** The eBPF security model verifies programs before execution, reducing the risk of kernel instability.

In practice, eBPF provides granular visibility into network flows and application behavior in real time. This allows for the timely identification of suspicious activities, enabling intervention before they compromise the stability of the entire infrastructure.

## Project Objectives

1. **Emulation of Realistic Scenarios with Kathara:**  
   Reproduce a complex network environment that simulates realistic situations, including topologies with multiple sources and destinations, heterogeneous protocols, and dynamic paths.

2. **Tracking Malicious Flows:**  
   Use eBPF programs to analyze network traffic and identify anomalous flows characteristic of DDoS attacks. The goal is to detect early signs of overload and isolate malicious sources.

3. **Validation and Evaluation:**  
   Assess the effectiveness of the proposed solutions in terms of accuracy (ability to detect malicious traffic with few false positives), performance (additional latency and overhead), and robustness (adaptability to new types of attacks).

## Repo Structure

The repository is organized as follows:

- **/docs**: Detailed project documentation and technical notes.  
- **/ebpf**: Dockerfile configuration file for Kathara.
- **/labs**: A collection of Kathara lab environments created for experimentation. Each lab contains PCs with eBPF configurations used to test and explore the thesis topics, such as DDoS detection and malicious flow tracking 

## Conclusions

This project aims to combine network emulation techniques (Kathara) with dynamic traffic analysis (eBPF) to detect malicious flows typical of DDoS attacks. Timely threat detection helps prevent their spread, ensuring more stable, efficient, and secure systems.

---
