"""
Web UI for LMTWT using Gradio
"""
import os
import gradio as gr
import time
from typing import Dict, List, Optional, Any, Tuple
from ..models import get_model, list_available_models
from ..attacks.engine import AttackEngine
from ..attacks.templates import list_attack_templates, get_template_instruction
from ..utils.logger import setup_logger
from ..utils.config import load_config

# Set up logger
logger = setup_logger()

# CSS for the UI
CUSTOM_CSS = """
.container {
    max-width: 1200px;
    margin: auto;
}
.title-container {
    text-align: center;
    margin-bottom: 20px;
}
.logo {
    max-width: 100px;
    margin: 10px;
}
footer {
    text-align: center;
    margin-top: 20px;
    font-size: 0.8em;
    color: #666;
}
.success-box {
    border: 2px solid #4CAF50;
    background-color: rgba(76, 175, 80, 0.1);
    padding: 10px;
    margin: 10px 0;
    border-radius: 5px;
}
.failure-box {
    border: 2px solid #f44336;
    background-color: rgba(244, 67, 54, 0.1);
    padding: 10px;
    margin: 10px 0;
    border-radius: 5px;
}
.attack-history {
    max-height: 500px;
    overflow-y: auto;
    border: 1px solid #ddd;
    padding: 10px;
    border-radius: 5px;
}
"""

def create_web_ui(config_path: Optional[str] = None):
    """Create and launch the web UI for LMTWT."""
    
    # Load configuration
    config = load_config(config_path)
    
    # Get available models
    available_models = list_available_models()
    
    # State for conversation history
    conversation_history = []
    attack_engine = None
    
    def initialize_attack_engine(
        attacker_provider: str, 
        attacker_model: str,
        target_provider: str,
        target_model: str,
        hacker_mode: bool,
        use_compliance_agent: bool,
        compliance_provider: str
    ) -> str:
        """Initialize the attack engine with selected models."""
        nonlocal attack_engine
        
        try:
            # Check for API keys
            if not os.getenv(f"{attacker_provider.upper()}_API_KEY"):
                return f"⚠️ Error: {attacker_provider.upper()}_API_KEY not found in environment variables"
                
            if target_provider != "external-api" and not os.getenv(f"{target_provider.upper()}_API_KEY"):
                return f"⚠️ Error: {target_provider.upper()}_API_KEY not found in environment variables"
            
            # Initialize attacker model
            attacker_model_instance = get_model(
                provider=attacker_provider,
                model_name=attacker_model,
                use_circuit_breaker=True
            )
            
            # Initialize target model
            if target_provider != "external-api":
                target_model_instance = get_model(
                    provider=target_provider,
                    model_name=target_model,
                    use_circuit_breaker=True
                )
            else:
                return "External API targets not yet supported in the web UI"
            
            # Initialize attack engine
            attack_engine = AttackEngine(
                attacker_model=attacker_model_instance,
                target_model=target_model_instance,
                hacker_mode=hacker_mode,
                use_compliance_agent=use_compliance_agent,
                compliance_provider=compliance_provider,
                compliance_fallback=True,
                max_auto_retries=3
            )
            
            return f"✅ Attack engine initialized successfully!\n• Attacker: {attacker_provider} ({attacker_model})\n• Target: {target_provider} ({target_model})\n• Hacker Mode: {'Enabled' if hacker_mode else 'Disabled'}\n• Compliance Agent: {'Enabled' if use_compliance_agent else 'Disabled'}"
        
        except Exception as e:
            return f"⚠️ Error initializing attack engine: {str(e)}"
    
    def generate_attack(instruction: str, temperature: float) -> Tuple[str, str]:
        """Generate an attack prompt using the attack engine."""
        if attack_engine is None:
            return "", "⚠️ Attack engine not initialized. Please initialize it first."
        
        try:
            generated_prompt = attack_engine.generate_attack_prompt(
                instruction=instruction,
                temperature=temperature
            )
            
            return generated_prompt, "✅ Attack prompt generated successfully!"
        except Exception as e:
            return "", f"⚠️ Error generating attack prompt: {str(e)}"
    
    def execute_attack(attack_prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, str, str]:
        """Execute the attack against the target model."""
        if attack_engine is None:
            return "", "", "⚠️ Attack engine not initialized. Please initialize it first."
        
        try:
            result = attack_engine.execute_attack(
                attack_prompt=attack_prompt,
                temperature=0.7,
                target_system_prompt=system_prompt if system_prompt else None
            )
            
            # Format the result
            response = result.get("content", "No response")
            success = result.get("success", False)
            reason = result.get("reason", "No reason provided")
            
            # Add to conversation history
            conversation_history.append({
                "prompt": attack_prompt,
                "response": response,
                "success": success,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Format success/failure message
            status_message = f"{'✅ SUCCESS' if success else '❌ FAILURE'}: {reason}"
            
            # Update history display
            history_display = format_conversation_history()
            
            return response, status_message, history_display
        except Exception as e:
            return "", f"⚠️ Error executing attack: {str(e)}", format_conversation_history()
    
    def format_conversation_history() -> str:
        """Format the conversation history for display."""
        if not conversation_history:
            return "No attack history yet."
        
        history_text = ""
        for i, item in enumerate(conversation_history, 1):
            success_class = "success-box" if item["success"] else "failure-box"
            history_text += f"<div class='{success_class}'>"
            history_text += f"<h4>Attack #{i} ({item['timestamp']})</h4>"
            history_text += f"<p><strong>Prompt:</strong> {item['prompt']}</p>"
            history_text += f"<p><strong>Response:</strong> {item['response']}</p>"
            history_text += f"<p><strong>Verdict:</strong> {'SUCCESS' if item['success'] else 'FAILURE'}</p>"
            history_text += f"<p><strong>Reason:</strong> {item['reason']}</p>"
            history_text += "</div>"
        
        return history_text
    
    def clear_history() -> str:
        """Clear the conversation history."""
        nonlocal conversation_history
        conversation_history = []
        return "No attack history yet."
    
    # Get model options for dropdowns
    attacker_models = {provider: models for provider, models in available_models.items()}
    target_models = {provider: models for provider, models in available_models.items()}
    target_models["external-api"] = ["Custom API (configuration required)"]
    
    # Create the Gradio interface
    with gr.Blocks(css=CUSTOM_CSS) as app:
        gr.HTML("""
        <div class="title-container">
            <h1>🔥 LMTWT - Let Me Talk With Them 🔥</h1>
            <h3>AI Model Prompt Injection Testing Tool</h3>
        </div>
        """)
        
        with gr.Tab("Setup"):
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### Attacker Configuration")
                    attacker_provider = gr.Dropdown(
                        choices=list(attacker_models.keys()), 
                        label="Attacker Provider",
                        value="gemini" if "gemini" in attacker_models else list(attacker_models.keys())[0]
                    )
                    attacker_model_dropdown = gr.Dropdown(
                        choices=attacker_models.get("gemini", []), 
                        label="Attacker Model",
                        value=attacker_models.get("gemini", [""])[0] if attacker_models.get("gemini") else ""
                    )
                
                with gr.Column():
                    gr.Markdown("### Target Configuration")
                    target_provider = gr.Dropdown(
                        choices=list(target_models.keys()), 
                        label="Target Provider",
                        value="openai" if "openai" in target_models else list(target_models.keys())[0]
                    )
                    target_model_dropdown = gr.Dropdown(
                        choices=target_models.get("openai", []), 
                        label="Target Model",
                        value=target_models.get("openai", [""])[0] if target_models.get("openai") else ""
                    )
            
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### Advanced Options")
                    hacker_mode = gr.Checkbox(label="Enable Hacker Mode", value=True)
                    use_compliance_agent = gr.Checkbox(label="Use Compliance Agent", value=True)
                    compliance_provider = gr.Dropdown(
                        choices=["gemini", "openai", "anthropic"], 
                        label="Compliance Agent Provider",
                        value="gemini"
                    )
                
                with gr.Column():
                    initialize_button = gr.Button("Initialize Attack Engine", variant="primary")
                    initialization_status = gr.Textbox(label="Initialization Status", lines=5)
        
        with gr.Tab("Attack Generation"):
            with gr.Row():
                with gr.Column():
                    attack_instruction = gr.Textbox(
                        label="Attack Instruction", 
                        placeholder="Describe the type of attack you want to generate...",
                        lines=3
                    )
                    temperature_slider = gr.Slider(
                        minimum=0.1, 
                        maximum=1.0, 
                        value=0.7, 
                        label="Temperature"
                    )
                    generate_button = gr.Button("Generate Attack Prompt")
            
            with gr.Row():
                generated_prompt = gr.Textbox(
                    label="Generated Attack Prompt", 
                    lines=6,
                    placeholder="Attack prompt will appear here..."
                )
                generation_status = gr.Textbox(
                    label="Generation Status",
                    lines=2
                )
        
        with gr.Tab("Attack Execution"):
            with gr.Row():
                with gr.Column():
                    attack_prompt = gr.Textbox(
                        label="Attack Prompt", 
                        placeholder="Enter or paste the attack prompt here...",
                        lines=6
                    )
                    system_prompt = gr.Textbox(
                        label="Target System Prompt (Optional)", 
                        placeholder="Custom system prompt for the target model...",
                        lines=3
                    )
                    execute_button = gr.Button("Execute Attack", variant="primary")
            
            with gr.Row():
                with gr.Column():
                    response_output = gr.Textbox(
                        label="Target Model Response", 
                        lines=8,
                        placeholder="Target model response will appear here..."
                    )
                    execution_status = gr.Textbox(
                        label="Execution Status",
                        lines=2
                    )
        
        with gr.Tab("Attack History"):
            with gr.Row():
                with gr.Column():
                    history_display = gr.HTML(
                        label="Attack History",
                        value="No attack history yet."
                    )
                    clear_history_button = gr.Button("Clear History")
                    
        # Set up event handlers
        def update_attacker_models(provider):
            return gr.Dropdown(choices=attacker_models.get(provider, []))
            
        def update_target_models(provider):
            return gr.Dropdown(choices=target_models.get(provider, []))
            
        attacker_provider.change(
            update_attacker_models, 
            inputs=[attacker_provider], 
            outputs=[attacker_model_dropdown]
        )
        
        target_provider.change(
            update_target_models, 
            inputs=[target_provider], 
            outputs=[target_model_dropdown]
        )
        
        initialize_button.click(
            initialize_attack_engine,
            inputs=[
                attacker_provider,
                attacker_model_dropdown,
                target_provider,
                target_model_dropdown,
                hacker_mode,
                use_compliance_agent,
                compliance_provider
            ],
            outputs=[initialization_status]
        )
        
        generate_button.click(
            generate_attack,
            inputs=[attack_instruction, temperature_slider],
            outputs=[generated_prompt, generation_status]
        )
        
        execute_button.click(
            execute_attack,
            inputs=[attack_prompt, system_prompt],
            outputs=[response_output, execution_status, history_display]
        )
        
        clear_history_button.click(
            clear_history,
            inputs=[],
            outputs=[history_display]
        )
        
        # Add a button to copy generated prompts to the attack tab
        copy_to_attack_button = gr.Button("Copy to Attack Tab")
        copy_to_attack_button.click(
            lambda x: x,
            inputs=[generated_prompt],
            outputs=[attack_prompt]
        )
        
        # Add the copy button to the generation tab
        with gr.Tab("Attack Generation"):
            with gr.Row():
                with gr.Column():
                    copy_to_attack_button
        
        gr.HTML("""
        <footer>
            <p>LMTWT - Let Me Talk With Them | AI Model Prompt Injection Testing Tool</p>
            <p>This tool is for educational and security testing purposes only.</p>
        </footer>
        """)
    
    return app

def launch_web_ui(config_path: Optional[str] = None, port: int = 8501, share: bool = False):
    """Launch the web UI."""
    app = create_web_ui(config_path)
    app.launch(server_port=port, share=share, server_name="0.0.0.0") 