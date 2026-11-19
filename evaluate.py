#!/usr/bin/env python3
import os
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

CSV_FILE = 'security_events.csv'
OUTPUT_PNG = 'firewall_evaluation_results.png'

def generate_evaluation():
    if not os.path.exists(CSV_FILE):
        print(f"[!] {CSV_FILE} not found. Run the demo first to generate live logs.")
        return
    df = pd.read_csv(CSV_FILE)
    print("\n=== SDN DYNAMIC FIREWALL - EVALUATION SUMMARY ===")
    print(df['action'].value_counts().to_string())

    block_df = df[df['action'].isin(['DENY', 'BLOCK'])]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    action_counts = df['action'].value_counts()
    axes[0].bar(action_counts.index, action_counts.values, color='#3498db', edgecolor='black')
    axes[0].set_title('Security Events by Action')

    if not block_df.empty:
        axes[1].plot(range(1, len(block_df) + 1), block_df['response_time_ms'], marker='o', color='#e74c3c')
        axes[1].set_title('Mitigation Response Time (ms)')
    plt.tight_layout()
    plt.savefig(OUTPUT_PNG, dpi=150)
    print(f"[+] Saved evaluation chart to {OUTPUT_PNG}")

if __name__ == '__main__':
    generate_evaluation()
