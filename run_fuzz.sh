#!/bin/bash
# HCP Cluster: Stealth Fuzzer Orchestrator
# Usage: ./run_fuzz.sh <URL> <FILTERS>

TARGET=${1:-"https://www.quimicaboss.com.mx/"}
FILTERS=${2:-"200,403,401"}
WORDLIST=${3:-"seclists_common.txt"}
DEPTH=${4:-2}
FUZZER_DIR="/cluster_data/fuzzer"
SBATCH_FILE="/cluster_data/fuzz_campaign.sbatch"

echo "--- 1. Configuring Fuzzing for $TARGET (Filters: $FILTERS, Wordlist: $WORDLIST, Depth: $DEPTH) ---"
# We update the sbatch script to use the passed arguments
cat <<EOF > $SBATCH_FILE
#!/bin/bash
#SBATCH --job-name=stealth_fuzz
#SBATCH --output=/cluster_data/fuzz_logs/%N_%j.log
#SBATCH --ntasks=62
#SBATCH --nodes=6

/usr/bin/srun $FUZZER_DIR/stealth_fuzzer -url "$TARGET" -filters "$FILTERS" -wordlist $FUZZER_DIR/wordlists/$WORDLIST -depth $DEPTH
EOF

echo "--- 2. Launching Campaign ---"
sbatch $SBATCH_FILE
echo "Job submitted! Check logs in /cluster_data/fuzz_logs/"
