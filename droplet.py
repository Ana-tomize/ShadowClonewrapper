from simple_term_menu import TerminalMenu
import os
import subprocess
from datetime import datetime
import time
import math

# Tool configuration
TOOL_CHAIN = {
    'subfinder': {
        'input_type': 'domains',
        'output_type': 'subdomains',
        'command': '/go/bin/subfinder -dL {INPUT} -silent -o {OUTPUT}'
    },
    'httpx': {
        'input_type': 'subdomains',
        'output_type': 'urls',
        'command': '/go/bin/httpx -l {INPUT} -silent -o {OUTPUT}'
    },
    'nuclei': {
        'input_type': 'urls',
        'output_type': 'vulnerabilities',
        'command': '/go/bin/nuclei -l {INPUT} -o {OUTPUT}'
    },
    'tlsx': {
        'input_type': 'domains',
        'output_type': 'tls_info',
        'command': '/go/bin/tlsx -l {INPUT} -o {OUTPUT}'
    },
    'dnsx': {
        'input_type': 'domains',
        'output_type': 'resolved',
        'command': '/go/bin/dnsx -l {INPUT} -resp -o {OUTPUT}'
    },
    'katana': {
        'input_type': 'urls',
        'output_type': 'crawled_urls',
        'command': '/go/bin/katana -list {INPUT} -jc -jsl -o {OUTPUT}'
    },
    'httprobe': {
        'input_type': 'subdomains',
        'output_type': 'live_urls',
        'command': 'cat {INPUT} | httprobe > {OUTPUT}'
    },
    'ffuf': {
        'input_type': 'urls',
        'output_type': 'fuzz_results',
        'command': '/usr/bin/ffuf -w {INPUT} -u {OUTPUT}'
    },
    'feroxbuster': {
        'input_type': 'urls',
        'output_type': 'directory_listing',
        'command': '/usr/bin/feroxbuster -u {INPUT} -o {OUTPUT}'
    },
    'dalfox': {
        'input_type': 'urls',
        'output_type': 'xss_results',
        'command': '/usr/bin/dalfox file {INPUT} -o {OUTPUT}'
    },
    'puredns': {
        'input_type': 'domains',
        'output_type': 'resolved_domains',
        'command': '/usr/bin/puredns resolve {INPUT} -w {OUTPUT}'
    },
    'nmap': {
        'input_type': 'ips',
        'output_type': 'scan_results',
        'command': '/usr/bin/nmap -iL {INPUT} -oN {OUTPUT}'
    },
    'trevorspray': {
        'input_type': 'users',
        'output_type': 'password_attempts',
        'command': '/usr/bin/trevorspray -U {INPUT} -o {OUTPUT}'
    },
    'massdns': {
        'input_type': 'domains',
        'output_type': 'dns_results',
        'command': '/usr/bin/massdns -r {INPUT} -o {OUTPUT}'
    },
    'fff': {
        'input_type': 'urls',
        'output_type': 'filtered_urls',
        'command': '/usr/bin/fff -d {INPUT} -o {OUTPUT}'
    }
}

class Scanner:
    def __init__(self):
        self.base_dir = os.path.expanduser('~/Targets/BugBounty')
        self.scans_dir = os.path.expanduser('~/Scans')
        self.max_retries = 3
        self.initial_backoff = 30  # seconds

    def get_line_count(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"Error: File {file_path} does not exist.")
                return 0

            result = subprocess.run(['wc', '-l', file_path], capture_output=True, text=True)
            return int(result.stdout.split()[0])
        except Exception as e:
            print(f"Error counting lines: {e}")
            return 0

    def calculate_processes(self, line_count):
        """
        Dynamic process scaling based purely on input size.
        More lines = more processes, with progressive scaling.
        """
        if line_count <= 0:
            return 1

        # Base calculation using logarithmic scaling
        # This gives a smoother curve as line count increases
        base = math.log(line_count + 1, 10)  # +1 to handle small numbers
        
        if line_count <= 100:
            # Very small files: minimal processes
            processes = max(1, min(5, line_count // 20))
            
        elif line_count <= 1000:
            # Small files: gradual scaling
            processes = int(10 * base)
            
        elif line_count <= 10000:
            # Medium files: increased scaling
            processes = int(30 * base)
            
        elif line_count <= 50000:
            # Large files: aggressive scaling
            processes = int(40 * base)
            
        else:
            # Very large files: maximum scaling
            processes = int(50 * base)

        # Tool-specific adjustments (multipliers instead of caps)
        tool_factors = {
            'httpx': 1.2,    # More aggressive for httpx
            'nuclei': 1.0,   # Standard scaling
            'subfinder': 0.8, # More conservative
            'default': 1.0
        }

        # Apply tool-specific factor
        factor = tool_factors.get(str(self.current_tool).lower(), tool_factors['default'])
        processes = int(processes * factor)

        # Ensure reasonable bounds
        processes = max(1, processes)

        print(f"\nProcess calculation for {self.current_tool}:")
        print(f"• Total lines: {line_count:,}")
        print(f"• Base processes: {processes}")
        print(f"• Tool factor: {factor}")
        print(f"• Lines per process: {line_count/processes:.1f}")

        return processes

    def validate_output(self, output_path):
        line_count = self.get_line_count(output_path)
        if line_count == 0:
            print(f"Error: Output file {output_path} is empty or invalid.")
            return False
        return True

    def get_previous_scan(self, output_dir, input_file_base):
        """Get the most recent previous scan file for comparison"""
        if not os.path.exists(output_dir):
            return None
        
        previous_scans = [
            f for f in os.listdir(output_dir)
            if f.startswith(input_file_base) and f.endswith('.txt')
        ]
        
        if not previous_scans:
            return None
            
        # Sort by timestamp in filename
        previous_scans.sort(reverse=True)
        return os.path.join(output_dir, previous_scans[0])

    def compare_results(self, current_file, previous_file):
        """Compare current scan results with previous scan"""
        if not previous_file:
            return None, 0
            
        try:
            with open(current_file, 'r') as curr, open(previous_file, 'r') as prev:
                current_lines = set(curr.read().splitlines())
                previous_lines = set(prev.read().splitlines())
                
            new_findings = current_lines - previous_lines
            return new_findings, len(new_findings)
        except Exception as e:
            print(f"Error comparing results: {e}")
            return None, 0

    def run_tool_with_retry(self, shadowclone_cmd, processes, output_path):
        """Run tool with automatic retry and process scaling on rate limits"""
        retries = 0
        current_processes = processes
        backoff_time = self.initial_backoff

        while retries < self.max_retries:
            try:
                # Run command showing real-time output directly to terminal
                process = subprocess.Popen(
                    shadowclone_cmd,
                    shell=True,
                    # Don't capture output - let it print directly to terminal
                    stdout=None,
                    stderr=None,
                    universal_newlines=True
                )
                
                # Wait for process to complete
                return_code = process.wait()
                
                if return_code != 0:
                    # Re-run with output capture just to check for rate limit
                    check_process = subprocess.run(
                        shadowclone_cmd, 
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    if "Rate exceeded" in check_process.stdout or "Rate exceeded" in check_process.stderr:
                        retries += 1
                        current_processes = max(5, current_processes // 2)
                        
                        print(f"\n⚠️ Rate limit exceeded. Attempt {retries}/{self.max_retries}")
                        print(f"Reducing concurrent processes to {current_processes}")
                        print(f"Waiting {backoff_time} seconds before retry...")
                        
                        time.sleep(backoff_time)
                        backoff_time *= 2  # Exponential backoff
                        
                        # Update command with new process count
                        shadowclone_cmd = shadowclone_cmd.replace(
                            f"-s {processes}", 
                            f"-s {current_processes}"
                        )
                    else:
                        print(f"\n❌ Error running tool (return code: {return_code})")
                        return False
                else:
                    return True

            except Exception as e:
                print(f"\n❌ Error running tool: {e}")
                return False
                
        print("\n❌ Max retries exceeded. Tool execution failed.")
        return False

    def run_tool(self, tool, input_path, platform, target, input_file):
        # Store current tool for process calculation
        self.current_tool = tool
        
        output_dir = os.path.join(self.scans_dir, target, f"{tool}_output")
        os.makedirs(output_dir, exist_ok=True)
        
        input_file_base = input_file.rsplit('.', 1)[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f"{input_file_base}_{timestamp}.txt")

        # Get previous scan for comparison
        previous_scan = self.get_previous_scan(output_dir, input_file_base)

        # Initial line count check
        line_count = self.get_line_count(input_path)
        if line_count == 0:
            print(f"Error: Input file {input_path} is empty or invalid.")
            return None

        print(f"Initial line count for {tool}: {line_count}")

        # Calculate processes for ShadowClone
        processes = self.calculate_processes(line_count)
        print(f"Calculated processes: {processes}")

        command = TOOL_CHAIN[tool]['command']
        shadowclone_cmd = (
            f"python ~/Tools/ShadowClone/shadowclone.py -i {input_path} -o {output_path} "
            f"-s {processes} -c \"{command}\""
        )

        print(f"\nRunning {tool} with {processes} processes")
        print(f"Command: {shadowclone_cmd}")

        if not self.run_tool_with_retry(shadowclone_cmd, processes, output_path):
            return None

        # Validate output
        if not self.validate_output(output_path):
            return None

        # Compare with previous scan
        new_findings, new_count = self.compare_results(output_path, previous_scan)
        
        print(f"Output saved to: {output_path}")
        if previous_scan:
            print(f"Compared to previous scan: {previous_scan}")
            print(f"New findings: {new_count}")
            if new_count > 0:
                print("\nNew results found:")
                for finding in sorted(new_findings):
                    print(f"  • {finding}")
        else:
            print("No previous scan found for comparison")
            
        return output_path

    def run(self):
        while True:
            choice = TerminalMenu(["Run Scan", "Exit"], title="Main Menu:").show()
            if choice == 1:
                break

            platforms = [d for d in os.listdir(self.base_dir) if os.path.isdir(os.path.join(self.base_dir, d))]
            platform = TerminalMenu(platforms, title="Select Platform:").show()
            if platform is None:
                continue

            platform_path = os.path.join(self.base_dir, platforms[platform])
            targets = [d for d in os.listdir(platform_path) if os.path.isdir(os.path.join(platform_path, d))]
            target = TerminalMenu(targets, title="Select Target:").show()
            if target is None:
                continue

            target_path = os.path.join(platform_path, targets[target])
            files = [f for f in os.listdir(target_path) if os.path.isfile(os.path.join(target_path, f))]
            input_file = TerminalMenu(files, title="Select Input File:").show()
            if input_file is None:
                continue

            tools = TerminalMenu(list(TOOL_CHAIN.keys()), title="Select Tools:", multi_select=True).show()
            if tools is None:
                continue

            current_input = os.path.join(target_path, files[input_file])
            for tool_index in tools:
                tool = list(TOOL_CHAIN.keys())[tool_index]
                result = self.run_tool(tool, current_input, platforms[platform], targets[target], files[input_file])
                if result:
                    current_input = result

if __name__ == '__main__':
    Scanner().run()
