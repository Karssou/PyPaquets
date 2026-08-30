<a id="readme-top"></a>

<!-- PROJECT LOGO / SCREENSHOT -->
<br />
<div align="center">
  <h3 align="center">PyPacket CLI</h3>

  <p align="center">
    A real-time Terminal UI Network Packet Sniffer & Analyzer built with Python, Scapy, and Rich.
    <br />
    <a href="https://github.com/Karssou/PyPackets"><strong>Explore the docs »</strong></a>
    <br />
    <br />
   
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
  
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

[![PyPacket Screen Shot][product-screenshot]](./docs/image.png)

**PyPacket** is a real-time network traffic analyzer running directly inside your terminal. Built as a CS50x Final Project, this command-line tool captures live network packets (both IPv4 and IPv6), applies custom BPF filters via CLI arguments, and renders an interactive Terminal User Interface (TUI) with reverse DNS resolution, real-time statistics, and top host rankings.

Key Features:

- **Asynchronous Sniffing:** Background packet capture powered by Scapy (`AsyncSniffer`) without locking the UI.
- **Dynamic CLI Filtering:** Easily isolate traffic by protocol (`--protocol`), port (`--port`), or target IP (`--ip`).
- **Reverse DNS Resolution:** Automatically translates raw IP addresses into human-readable hostnames using non-blocking cached resolution (`lru_cache`).
- **Host Identification:** Detects the host machine's local IPv4 and IPv6 addresses and tags them with a highlighted `Vous` / `You` badge.
- **Live Inspection Controls:** Pause and resume live rendering instantly by pressing `SPACE` without dropping background capture.
- **Top Talkers Dashboard:** Displays the top 5 most active hosts in real time alongside the main traffic log.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

This project relies on core Python networking and TUI libraries:

- [![Python][Python-badge]][Python-url]
- [![Scapy][Scapy-badge]][Scapy-url]
- [![Rich][Rich-badge]][Rich-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

Follow these instructions to set up and run PyPacket locally.

### Prerequisites

- **Python 3.10+** installed on your system.
- **Administrator / Root privileges** (`sudo` on Linux/macOS or Administrator Terminal on Windows) required for low-level network interface packet interception.
- **libpcap** (Linux/macOS) or **Npcap** (Windows) for full BPF filtering support.

### Installation

1. Clone the repository:
   ```sh
   git clone [https://github.com/your_username/pypacket-cli.git](https://github.com/your_username/pypacket-cli.git)
   cd pypacket-cli
   ```
