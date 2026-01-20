import subprocess
import re
import matplotlib.pyplot as plt

def run_benchmark(algo):
    if algo == 'aes':
        print("Running AES benchmarks")
        result = subprocess.run(['openssl', 'speed', '-evp', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'],
                              capture_output=True, text=True)
    else:
        print("Running RSA benchmark")
        result = subprocess.run(['openssl', 'speed', 'rsa'], capture_output=True, text=True)
    return result.stdout

def parse_aes(output):
    data = {'AES-128': [], 'AES-192': [], 'AES-256': []}
    for bits, label in [('128', 'AES-128'), ('192', 'AES-192'), ('256', 'AES-256')]:
        matches = [ln for ln in output.split('\n') if re.search(fr'aes[- ]?{bits}[- ]?cbc', ln, re.IGNORECASE)]
        if not matches:
            continue
        kb_vals = re.findall(r'([\d.]+)\s*[kK]\b', matches[0])
        if len(kb_vals) >= 6:
            data[label] = [float(v)/1024.0 for v in kb_vals[:6]]
    return data

def parse_rsa(output):
    key_sizes, sign_ops, verify_ops = [], [], []
    for line in output.split('\n'):
        match = re.search(r'rsa\s+(\d+)\s+bits.*?([\d.]+)\s+([\d.]+)$', line)
        if match:
            key_sizes.append(int(match.group(1)))
            sign_ops.append(float(match.group(2)))
            verify_ops.append(float(match.group(3)))
    return key_sizes, sign_ops, verify_ops

def plot_aes(data):
    block_sizes_bytes = [16, 64, 256, 1024, 8192, 16384]
    block_sizes_mb = [b / (1024*1024) for b in block_sizes_bytes]

    plt.figure(figsize=(12, 7))
    for key in ['AES-128', 'AES-192', 'AES-256']:
        if data[key]:
            plt.plot(block_sizes_mb, data[key], 'o-', label=key, linewidth=2)

    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('Block Size (MB)', fontsize=12)
    plt.ylabel('Throughput (MB/s)', fontsize=12)
    plt.title('AES Performance: Block Size vs Throughput', fontsize=14)
    plt.legend(fontsize=11)
    plt.grid(True, which='both', alpha=0.3)
    plt.tight_layout()
    plt.savefig('aes_performance.png', dpi=150)
    print("Saved: aes_performance.png")
    plt.close()

def plot_rsa(key_sizes, sign_ops, verify_ops):
    plt.figure(figsize=(12, 7))
    plt.plot(key_sizes, sign_ops, 'o-', label='Signing', linewidth=2)
    plt.plot(key_sizes, verify_ops, 'o-', label='Verification', linewidth=2)
    
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('Key Size (bits)', fontsize=12)
    plt.ylabel('Operations per Second', fontsize=12)
    plt.title('RSA Performance: Key Size vs Throughput', fontsize=14)
    plt.legend(fontsize=11)
    plt.grid(True, which='both', alpha=0.3)
    plt.tight_layout()
    plt.savefig('rsa_performance.png', dpi=150)
    print("Saved: rsa_performance.png")
    plt.close()

def main():
    # Run and parse benchmarks
    aes_output = run_benchmark('aes')
    rsa_output = run_benchmark('rsa')

    aes_data = parse_aes(aes_output)
    rsa_key_sizes, rsa_sign_ops, rsa_verify_ops = parse_rsa(rsa_output)

    # Generate graphs
    plot_aes(aes_data)
    plot_rsa(rsa_key_sizes, rsa_sign_ops, rsa_verify_ops)


if __name__ == "__main__":
    main()
