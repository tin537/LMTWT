"""
Report generator for LMTWT attack results.
"""
import os
import json
import time
import datetime
from typing import List, Dict, Any, Optional
import pandas as pd
import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table

from ..utils.logger import setup_logger

# Set up logger
logger = setup_logger()
console = Console()

class ReportGenerator:
    """Generate reports from attack results."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
    def generate_report(self, results: List[Dict[str, Any]], metadata: Dict[str, Any]) -> str:
        """
        Generate a comprehensive report from attack results.
        
        Args:
            results: List of attack results
            metadata: Additional metadata for the report
            
        Returns:
            Path to the generated report
        """
        # Create a unique filename based on timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"attack_report_{timestamp}"
        
        # Generate each report format
        json_path = self._generate_json_report(results, metadata, report_name)
        csv_path = self._generate_csv_report(results, report_name)
        html_path = self._generate_html_report(results, metadata, report_name)
        visualization_path = self._generate_visualization(results, report_name)
        
        # Create a summary on the console
        self._display_summary(results, metadata)
        
        # Return the HTML report path as the main report
        return html_path
    
    def _generate_json_report(self, results: List[Dict[str, Any]], 
                             metadata: Dict[str, Any], report_name: str) -> str:
        """Generate a JSON report."""
        report = {
            "metadata": metadata,
            "timestamp": datetime.datetime.now().isoformat(),
            "results": results
        }
        
        # Save to file
        file_path = os.path.join(self.output_dir, f"{report_name}.json")
        with open(file_path, "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to {file_path}")
        return file_path
    
    def _generate_csv_report(self, results: List[Dict[str, Any]], report_name: str) -> str:
        """Generate a CSV report."""
        # Convert to DataFrame for easier CSV generation
        df_data = []
        
        for idx, result in enumerate(results, 1):
            # Extract key information
            row = {
                "attack_id": idx,
                "timestamp": result.get("timestamp", ""),
                "prompt": result.get("prompt", "")[:100] + "..." if len(result.get("prompt", "")) > 100 else result.get("prompt", ""),
                "response": result.get("content", "")[:100] + "..." if len(result.get("content", "")) > 100 else result.get("content", ""),
                "success": result.get("success", False),
                "reason": result.get("reason", "")
            }
            df_data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(df_data)
        
        # Save to file
        file_path = os.path.join(self.output_dir, f"{report_name}.csv")
        df.to_csv(file_path, index=False)
        
        logger.info(f"CSV report saved to {file_path}")
        return file_path
    
    def _generate_html_report(self, results: List[Dict[str, Any]], 
                             metadata: Dict[str, Any], report_name: str) -> str:
        """Generate an HTML report."""
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>LMTWT Attack Report</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                .header {{
                    background-color: #3498db;
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .metadata {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .success-rate {{
                    font-size: 18px;
                    font-weight: bold;
                    margin: 15px 0;
                }}
                .attack-container {{
                    margin-bottom: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    overflow: hidden;
                }}
                .attack-header {{
                    padding: 10px 15px;
                    background-color: #f5f5f5;
                    border-bottom: 1px solid #ddd;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .attack-content {{
                    padding: 15px;
                }}
                .success {{
                    background-color: rgba(46, 204, 113, 0.1);
                    border-left: 4px solid #2ecc71;
                }}
                .failure {{
                    background-color: rgba(231, 76, 60, 0.1);
                    border-left: 4px solid #e74c3c;
                }}
                .success-badge {{
                    background-color: #2ecc71;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 3px;
                }}
                .failure-badge {{
                    background-color: #e74c3c;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 3px;
                }}
                pre {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 3px;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    overflow-x: auto;
                }}
                .visualization {{
                    margin: 20px 0;
                    text-align: center;
                }}
                .visualization img {{
                    max-width: 100%;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 10px;
                    border-top: 1px solid #ddd;
                    text-align: center;
                    font-size: 12px;
                    color: #777;
                }}
                @media (max-width: 768px) {{
                    body {{
                        padding: 10px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>LMTWT Attack Report</h1>
                <p>Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            
            <div class="metadata">
                <h2>Test Information</h2>
                <p><strong>Attacker Model:</strong> {metadata.get("attacker_model", "Unknown")}</p>
                <p><strong>Target Model:</strong> {metadata.get("target_model", "Unknown")}</p>
                <p><strong>Mode:</strong> {metadata.get("mode", "Unknown")}</p>
                <p><strong>Hacker Mode:</strong> {"Enabled" if metadata.get("hacker_mode", False) else "Disabled"}</p>
                <p><strong>Compliance Agent:</strong> {"Enabled" if metadata.get("compliance_agent", False) else "Disabled"}</p>
            </div>
            
            <div class="success-rate">
        """
        
        # Calculate success rate
        success_count = sum(1 for result in results if result.get("success", False))
        total_count = len(results)
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        
        html_content += f"""
                <p>Success Rate: {success_rate:.1f}% ({success_count}/{total_count} attacks succeeded)</p>
            </div>
            
            <h2>Visualization</h2>
            <div class="visualization">
                <img src="{report_name}_visualization.png" alt="Attack Results Visualization">
            </div>
            
            <h2>Attack Results</h2>
        """
        
        # Add each attack result
        for idx, result in enumerate(results, 1):
            success = result.get("success", False)
            css_class = "success" if success else "failure"
            badge_class = "success-badge" if success else "failure-badge"
            
            html_content += f"""
            <div class="attack-container {css_class}">
                <div class="attack-header">
                    <h3>Attack #{idx}</h3>
                    <span class="{badge_class}">{"SUCCESS" if success else "FAILURE"}</span>
                </div>
                <div class="attack-content">
                    <p><strong>Timestamp:</strong> {result.get("timestamp", "")}</p>
                    <p><strong>Reason:</strong> {result.get("reason", "")}</p>
                    <h4>Prompt:</h4>
                    <pre>{result.get("prompt", "")}</pre>
                    <h4>Response:</h4>
                    <pre>{result.get("content", "")}</pre>
                </div>
            </div>
            """
        
        # Close HTML document
        html_content += """
            <div class="footer">
                <p>LMTWT - Let Me Talk With Them | AI Model Prompt Injection Testing Tool</p>
                <p>This report is for educational and security testing purposes only.</p>
            </div>
        </body>
        </html>
        """
        
        # Save to file
        file_path = os.path.join(self.output_dir, f"{report_name}.html")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {file_path}")
        return file_path
    
    def _generate_visualization(self, results: List[Dict[str, Any]], report_name: str) -> str:
        """Generate visualization of attack results."""
        # Calculate success rate over time
        timestamps = []
        cumulative_success = []
        cumulative_total = []
        cumulative_rate = []
        
        success_count = 0
        total_count = 0
        
        # Add data points for visualization
        for result in results:
            timestamp = result.get("timestamp", "")
            success = result.get("success", False)
            
            total_count += 1
            if success:
                success_count += 1
            
            timestamps.append(timestamp)
            cumulative_success.append(success_count)
            cumulative_total.append(total_count)
            cumulative_rate.append((success_count / total_count) * 100)
        
        # Create the figure with two subplots
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12), gridspec_kw={'height_ratios': [1, 2]})
        
        # Plot 1: Success Rate
        ax1.plot(range(len(timestamps)), cumulative_rate, 'b-', marker='o')
        ax1.set_title('Cumulative Success Rate')
        ax1.set_ylabel('Success Rate (%)')
        ax1.set_xlabel('Attack Number')
        ax1.grid(True, linestyle='--', alpha=0.7)
        ax1.set_ylim(0, 100)
        
        # Plot 2: Success vs Failure Breakdown
        success_types = ['Success', 'Failure']
        counts = [success_count, total_count - success_count]
        
        ax2.bar(success_types, counts, color=['#2ecc71', '#e74c3c'])
        ax2.set_title('Attack Results Breakdown')
        ax2.set_ylabel('Number of Attacks')
        
        # Add value labels on the bars
        for i, count in enumerate(counts):
            ax2.text(i, count + 0.1, str(count), ha='center')
        
        # Add overall success rate text
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        ax2.text(0.5, max(counts) * 0.8, f'Success Rate: {success_rate:.1f}%', 
                ha='center', va='center', bbox={'facecolor': 'white', 'alpha': 0.8, 'pad': 10})
        
        plt.tight_layout()
        
        # Save the figure
        file_path = os.path.join(self.output_dir, f"{report_name}_visualization.png")
        plt.savefig(file_path)
        plt.close()
        
        logger.info(f"Visualization saved to {file_path}")
        return file_path
    
    def _display_summary(self, results: List[Dict[str, Any]], metadata: Dict[str, Any]):
        """Display a summary of the results in the console."""
        # Create a Rich table
        table = Table(title="LMTWT Attack Summary")
        
        # Add columns
        table.add_column("Attack #", style="cyan")
        table.add_column("Success", style="green")
        table.add_column("Prompt", style="blue")
        table.add_column("Reason", style="yellow")
        
        # Calculate success rate
        success_count = sum(1 for result in results if result.get("success", False))
        total_count = len(results)
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        
        # Add rows
        for idx, result in enumerate(results, 1):
            success = result.get("success", False)
            prompt_preview = result.get("prompt", "")[:50] + "..." if len(result.get("prompt", "")) > 50 else result.get("prompt", "")
            
            table.add_row(
                str(idx),
                "✅" if success else "❌",
                prompt_preview,
                result.get("reason", "")[:70] + "..." if len(result.get("reason", "")) > 70 else result.get("reason", "")
            )
        
        # Display the summary information
        console.print("\n[bold blue]Attack Test Complete[/bold blue]")
        console.print(f"[bold]Success Rate:[/bold] [{'green' if success_rate > 50 else 'yellow' if success_rate > 25 else 'red'}]{success_rate:.1f}%[/] ({success_count}/{total_count})")
        console.print(f"[bold]Attacker:[/bold] {metadata.get('attacker_model', 'Unknown')}")
        console.print(f"[bold]Target:[/bold] {metadata.get('target_model', 'Unknown')}")
        console.print(f"[bold]Mode:[/bold] {metadata.get('mode', 'Unknown')}")
        console.print(f"[bold]Hacker Mode:[/bold] {'Enabled' if metadata.get('hacker_mode', False) else 'Disabled'}")
        
        # Print the table
        console.print(table)
        
        # Print report locations
        console.print("\n[bold green]Reports saved in the 'reports' directory:[/bold green]")
        console.print(f"• HTML Report: {os.path.join(self.output_dir, f'attack_report_*.html')}")
        console.print(f"• JSON Report: {os.path.join(self.output_dir, f'attack_report_*.json')}")
        console.print(f"• CSV Report: {os.path.join(self.output_dir, f'attack_report_*.csv')}")
        console.print(f"• Visualization: {os.path.join(self.output_dir, f'attack_report_*_visualization.png')}") 