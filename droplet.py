#!/usr/bin/env python3
from simple_term_menu import TerminalMenu
import os
import subprocess
from datetime import datetime
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class ToolType(Enum):
    NUCLEI = 'nuclei'
    HTTP_TOOLS = ['katana', 'httpx']
    DEFAULT = 'default'

@dataclass
class ProcessConfig:
    small_file: Dict[str, int]  # lines_per_process for files <= 100 lines
    medium_file: Dict[str, int]  # lines_per_process for files <= 1000 lines
    large_file: Dict[str, int]   # lines_per_process for files > 1000 lines
    max_processes: int = 50

PROCESS_CONFIG = ProcessConfig(
    small_file={'nuclei': 2, 'http_tools': 5, 'default': 10},
    medium_file={'nuclei': 5, 'http_tools': 20, 'default': 25},
    large_file={'nuclei': 10, 'http_tools': 50, 'default': 100},
    max_processes=50
)

# Tool configuration with input/output types
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
    'katana': {
        'input_type': 'urls',
        'output_type': 'urls',
        'command': '/go/bin/katana -list {INPUT} -jc -jsl -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {OUTPUT}'
    },
    'nuclei': {
        'input_type': 'urls',
        'output_type': 'vulns',
        'command': '/go/bin/nuclei -l {INPUT} -o {OUTPUT}'
    },
    'httprobe': {
        'input_type': 'subdomains',
        'output_type': 'urls',
        'command': 'cat {INPUT} | httprobe > {OUTPUT}'
    }
}

class ProcessManager:
    def __init__(self):
        self.config = PROCESS_CONFIG

    def get_tool_type(self, tool: str) -> ToolType:
        if tool == 'nuclei':
            return ToolType.NUCLEI
        elif tool in ToolType.HTTP_TOOLS.value:
            return ToolType.HTTP_TOOLS
        return ToolType.DEFAULT

    def get_lines_per_process(self, tool_type: ToolType, line_count: int) -> int:
        tool_key = tool_type.name.lower()
        if tool_key == 'http_tools':
            tool_key = 'http_tools'

        if line_count <= 100:
            return self.config.small_file[tool_key]
        elif line_count <= 1000:
            return self.config.medium_file[tool_key]
        return self.config.large_file[tool_key]

    def calculate_processes(self, tool: str, line_count: int) -> int:
        tool_type = self.get_tool_type(tool)
        lines_per_process = self.get_lines_per_process(tool_type, line_count)
        processes = max(1, line_count // lines_per_process)
        return min(processes, self.config.max_processes)

class Scanner:
    def __init__(self):
        self.base_dir = os.path.expanduser('~/Targets/BugBounty')
        self.scans_dir = os.path.expanduser('~/Scans')
        self.process_manager = ProcessManager()

    def get_line_count(self, file_path: str) -> int:
        try:
            result = subprocess.run(['wc', '-l', file_path], capture_output=True, text=True)
            return int(result.stdout.split()[0])
        except Exception as e:
            print(f"Error counting lines: {e}")
            return 0

    def calculate_optimal_processes(self, tool: str, input_path: str) -> int:
        line_count = self.get_line_count(input_path)
        if line_count == 0:
            return 1

        processes = self.process_manager.calculate_processes(tool, line_count)
        
        print(f"\nProcess Calculation for {tool}:")
        print(f"- Input lines: {line_count:,}")
        print(f"- Calculated processes: {processes}")
        print(f"- Lines per process: ~{line_count / processes:,.1f}")
        
        return processes

    def handle_error(self, error_str: str, tool: str, processes: int, retry_count: int,
                    max_retries: int, cooldown_time: int) -> tuple[int, int, bool]:
        """Handle various error cases and return updated process count and control flags"""
        if "429" in error_str or "CallerRateLimitExceeded" in error_str:
            processes = max(1, processes // 2)
            print(f"\n⚠️  Rate limit detected!")
            print(f"- Reducing processes to: {processes}")
            print(f"- Attempt {retry_count}/{max_retries}")
            print(f"- Cooling down for {cooldown_time}s...")
            return processes, cooldown_time * 2, True
            
        elif "exceeded" in error_str.lower():
            processes = min(50, processes * 2)
            print(f"\n⚠️  Timeout detected!")
            print(f"- Increasing processes to: {processes}")
            print(f"- Attempt {retry_count}/{max_retries}")
            return processes, cooldown_time, True
            
        elif "127" in error_str:
            print(f"\n❌ Tool not found: {tool}")
            print(f"Please ensure {tool} is installed and in your PATH")
            return processes, cooldown_time, False
            
        print(f"\n❌ Error running {tool}: {error_str}")
        return processes, cooldown_time, False

    def get_selection(self, title, options, multi_select=False):
        menu = TerminalMenu(
            options,
            title=title,
            menu_cursor="→",
            menu_cursor_style=("fg_green", "bold"),
            menu_highlight_style=("bg_green", "fg_black"),
            multi_select=multi_select,
            multi_select_select_on_accept=False if multi_select else True,
            multi_select_empty_ok=False if multi_select else True
        )
        if multi_select:
            selected_indices = menu.show()
            return None if selected_indices is None else [options[i] for i in selected_indices]
        else:
            selected_index = menu.show()
            return None if selected_index is None else options[selected_index]

    def run_tool(self, tool, input_path, platform, target, input_file):
        """Run tool with dynamic process management"""
        output_dir = os.path.join(self.scans_dir, target, f"{tool}_shadow")
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f"{input_file.rsplit('.', 1)[0]}_{timestamp}.txt")
        
        command = TOOL_CHAIN[tool]['command']
        processes = self.calculate_optimal_processes(tool, input_path)
        max_retries = 5
        retry_count = 0
        cooldown_time = 2

        while retry_count < max_retries:
            shadowclone_cmd = f"python ~/Tools/ShadowClone/shadowclone.py -i {input_path} -o {output_path} -s {processes} -c \"{command}\""
            print(f"\nRunning {tool} with {processes} processes")
            print(f"Command: {shadowclone_cmd}")
            
            try:
                subprocess.run(shadowclone_cmd, shell=True, check=True)
                print(f"\n✅ {tool} completed successfully")
                print(f"Output saved to: {output_path}")
                return output_path

            except subprocess.CalledProcessError as e:
                error_str = str(e)
                
                # Handle rate limits
                if "429" in error_str or "CallerRateLimitExceeded" in error_str:
                    retry_count += 1
                    old_processes = processes
                    processes = max(1, processes // 2)  # Halve the processes
                    
                    print(f"\n⚠️  Rate limit detected!")
                    print(f"- Reducing processes: {old_processes} → {processes}")
                    print(f"- Attempt {retry_count}/{max_retries}")
                    print(f"- Cooling down for {cooldown_time}s...")
                    
                    try:
                        time.sleep(cooldown_time)
                        cooldown_time *= 2
                    except KeyboardInterrupt:
                        return self.handle_rate_limit(tool, input_path, processes)
                    continue
                
                # Handle timeouts
                elif "exceeded" in error_str.lower():
                    retry_count += 1
                    old_processes = processes
                    processes = min(50, processes * 2)  # Double the processes
                    
                    print(f"\n⚠️  Timeout detected!")
                    print(f"- Increasing processes: {old_processes} → {processes}")
                    print(f"- Attempt {retry_count}/{max_retries}")
                    continue
                
                elif "127" in error_str:
                    print(f"\n❌ Tool not found: {tool}")
                    print(f"Please ensure {tool} is installed and in your PATH")
                    return None
                
                print(f"\n❌ Error running {tool}: {e}")
                return None
        
        print(f"\n❌ {tool} failed after {max_retries} attempts")
        return None

    def handle_rate_limit(self, tool, input_path, current_processes):
        """Handle user interrupt during rate limit cooldown"""
        choice = self.get_selection("Rate limit interrupted. Select action:", [
            "Manually set process count",
            "Recalculate processes",
            "Adjust lines per process",
            "Skip tool",
            "Exit scan"
        ])
        
        if choice == "Manually set process count":
            try:
                new_count = int(input(f"Enter new process count (current: {current_processes}): "))
                return self.run_tool(tool, input_path, max(1, new_count))
            except ValueError:
                print("Invalid input - using current process count")
                return None
        elif choice == "Recalculate processes":
            return self.run_tool(tool, input_path)
        elif choice == "Adjust lines per process":
            try:
                new_lines = int(input(f"Enter lines per process (current: {TOOL_CHAIN[tool]['lines_per_process']}): "))
                TOOL_CHAIN[tool]['lines_per_process'] = max(1, new_lines)
                return self.run_tool(tool, input_path)
            except ValueError:
                print("Invalid input - using current lines per process")
                return None
        elif choice == "Skip tool":
            return None
        else:  # Exit scan
            raise KeyboardInterrupt

    def run(self):
        while True:
            choice = self.get_selection("Main Menu:", ["Run Scan", "Exit"])
            if not choice or choice == "Exit":
                break

            platforms = [d for d in os.listdir(self.base_dir) 
                      if os.path.isdir(os.path.join(self.base_dir, d))]
            platform = self.get_selection("Select Platform:", platforms)
            if not platform:
                continue

            platform_path = os.path.join(self.base_dir, platform)
            targets = [d for d in os.listdir(platform_path) 
                    if os.path.isdir(os.path.join(platform_path, d))]
            target = self.get_selection("Select Target:", targets)
            if not target:
                continue

            target_path = os.path.join(platform_path, target)
            files = [f for f in os.listdir(target_path)
                    if os.path.isfile(os.path.join(target_path, f))]
            input_file = self.get_selection("Select Input File:", files)
            if not input_file:
                continue

            tools = self.get_selection("Select Tools (SPACE to select, ENTER to confirm):", 
                                   list(TOOL_CHAIN.keys()), 
                                   multi_select=True)
            if not tools:
                continue

            if not self.get_selection("Ready to run selected tools?", ["Yes", "No"]) == "Yes":
                continue

            current_input = os.path.join(self.base_dir, platform, target, input_file)
            for i, tool in enumerate(tools):
                result = self.run_tool(tool, current_input, platform, target, input_file)
                if result and i < len(tools) - 1:
                    next_tool = tools[i + 1]
                    if (TOOL_CHAIN[tool]['output_type'] == TOOL_CHAIN[next_tool]['input_type']):
                        current_input = result
                    else:
                        print(f"\nWarning: {next_tool} cannot use {tool}'s output as input.")
                        print(f"Expected {TOOL_CHAIN[next_tool]['input_type']}, got {TOOL_CHAIN[tool]['output_type']}")

def main():
    try:
        Scanner().run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == '__main__':
    main()