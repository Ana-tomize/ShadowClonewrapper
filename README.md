# ShadowClonewrapper

🚀 A collection of Python tools designed to enhance your security testing with AWS lambda. This repository contains two main tools: Droplet and Drought, both built to assist your operations through interactive terminal interfaces.



## 🛠️ ShadowClone Configuration

Before using the tools, you'll need to configure ShadowClone with the custom Dockerfile that includes all necessary security tools:

1. Replace the default `Dockerfile_v0.2` in your ShadowClone directory with the updated version that includes:
   - Go-based tools
   - Additional utilities and dependencies
   - Pre-configured resolvers and templates

Key additions in the custom Dockerfile:
- Go installation
- tools:
  - subfinder
  - httpx
  - nuclei (with templates)
  - tlsx
  - dnsx
  - katana
  - httprobe
  - ffuf
  - feroxbuster
  - dalfox
  - puredns
  - nmap
  - trevorspray
  - massdns
- Pre-configured resolvers and nuclei templates

```bash
# Copy the custom Dockerfile
cp Dockerfile_v0.2 /path/to/your/ShadowClone/
```



## 🔧 Tools Overview

### 🌊 Droplet
A wrapper for shadowclone tool to orchestrate the execution of multiple security tools in sequence. Perfect for recon and automation.

### 🏜️ Drought
A AWS S3 bucket cleaner that provides an interactive interface for efficiently cleaning up and managing S3 buckets and their contents.

## 🚀 Quick Start

1. Clone the repository:
```bash
git clone https://github.com/Ana-tomize/ShadowClonewrapper.git
cd ShadowClonewrapper
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the scripts executable:
```bash
chmod +x droplet.py drought.py
```

## 🎯 Droplet: Security Tool  

### Key Features
- **🧠 Smart Process Management**
  - Dynamic process optimization based on input size
  - Adaptive scaling for different tool types

### Usage
```bash
./droplet.py
```

### Process Management Tiers
| File Size   | Nuclei | HTTP Tools | Default |
|------------|--------|------------|----------|
| Small ≤100 | 2/proc | 5/proc     | 10/proc  |
| Med ≤1000  | 5/proc | 20/proc    | 25/proc  |
| Large >1000| 10/proc| 50/proc    | 100/proc |

### Directory Structure
```
~/Targets/BugBounty/
└── [Platform]
    └── [Target]
        └── [Input Files]

~/Scans/
└── [Target]
    └── [Tool]_shadow
        └── [Scan Results]
```

## 💧 Drought: AWS S3 Manager

### Key Features

- **⚡ Efficient Operations**
  - Bulk deletion capabilities
  - Automatic pagination

### Usage
```bash
./drought.py
```

### Navigation
- ⬆️⬇️ Arrow keys to navigate
- ↩️ Enter to select
- ⎋ ESC to go back/exit

## 🛠️ Prerequisites

### For Droplet
- Python 3.6+
- simple-term-menu
- Security tools in PATH:
  - subfinder
  - httpx
  - katana
  - nuclei
  - httprobe
  - dalfox
    

### For Drought
- Python 3.6+
- boto3 ≥ 1.26.0
- simple-term-menu ≥ 1.6.0
- Drought.py requires you to login with appropriate AWS IAM permissions on aws cli🔐 

## 🔄 Tool Chain Configuration

```python
{
    'subfinder': {'input_type': 'domains', 'output_type': 'subdomains'},
    'httpx': {'input_type': 'subdomains', 'output_type': 'urls'},
    'katana': {'input_type': 'urls', 'output_type': 'urls'},
    'nuclei': {'input_type': 'urls', 'output_type': 'vulns'},
    'httprobe': {'input_type': 'subdomains', 'output_type': 'urls'}
}
```

---
Made with ❤️ by Ana-tomize
