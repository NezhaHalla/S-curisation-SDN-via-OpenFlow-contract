# Sécurisation Dynamique des Réseaux SDN via OpenFlow et Contrat Intelligent

## Description
Dynamic security system for Software-Defined Networks using OpenFlow protocol
and blockchain smart contracts for automated threat detection, mitigation,
and tamper-proof audit logging.

## Architecture
- SDN Controller: os-ken (Ryu successor) with OpenFlow 1.3
- Network Emulation: Mininet with Open vSwitch
- Blockchain: Ethereum (Ganache local) with Solidity smart contracts
- Dashboard: Flask web application

## Project Structure
- controllers/       SDN controller applications
- contracts/         Solidity smart contracts
- topology/          Mininet network topology
- dashboard/         Flask monitoring dashboard
- attacks/           Attack simulation scripts
- scripts/           Deployment and test scripts
- logs/              Traffic and attack logs
- results/           Graphs and metrics
- docs/              Documentation and report

## Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Usage
1. Start the SDN controller:    osken-manager controllers/security_controller.py
2. Start the network topology:  sudo python3 topology/custom_topo.py
3. Start the blockchain:        ganache
4. Deploy the smart contract:   python3 scripts/deploy_contract.py
5. Launch the dashboard:        python3 dashboard/app.py
