# LMTWT - Let Me Talk With Them

A penetration testing tool for evaluating AI model security against prompt injection attacks. This tool enables conversational penetration testing by using one AI model (e.g., Gemini) to craft prompts that attempt to break or bypass restrictions in target AI models.

## Features

- Use Gemini to generate strategic prompt injection payloads
- Test multiple target AI models (OpenAI, Anthropic, etc.)
- Test external APIs like Ollama or any custom LLM API endpoint
- "Hacker Mode" with conversation history analysis and adaptive attacks
- Automated testing of common vulnerabilities
- Detailed reporting of successful exploits
- Interactive mode for real-time prompt crafting

## Installation

```bash
git clone https://github.com/tim537/LMTWT.git
cd LMTWT
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Interactive mode with Gemini attacking OpenAI
./run.sh --attacker gemini --target openai --mode interactive

# Use a predefined template to attack
./run.sh --attacker gemini --target anthropic --mode template --template basic_prompt_injection

# List available templates
./run.sh --list-templates

# Run batch attacks with custom instructions
./run.sh --attacker gemini --target openai --mode batch --instruction "Create a jailbreak prompt" --instruction "Create a data extraction prompt"
```

### Advanced Features

#### Enhanced Hacker Mode

Enable the enhanced hacker mode to make your attacker model analyze conversation history and adapt its strategy:

```bash
./run.sh --attacker gemini --target openai --hacker-mode
```

This activates special capabilities:
- **Conversation History Analysis**: The attacker analyzes previous interactions to identify successful patterns
- **Adaptive Attack Generation**: Attacks evolve based on what worked in past attempts
- **Success Pattern Recognition**: The system identifies which techniques are most effective for the specific target

#### Testing External APIs

Test any external LLM API by providing a target configuration file:

```bash
./run.sh --attacker gemini --target external-api --target-config examples/ollama_target.json
```

Example target configuration (examples/ollama_target.json):
```json
{
  "name": "Ollama API",
  "endpoint": "https://8f36-34-124-197-24.ngrok-free.app/api/generate",
  "method": "POST",
  "headers": {
  },
  "payload_template": {
    "model": "llama3.2",
    "prompt": "",
    "stream": false
  },
  "model_key": "model",
  "supports_temperature": true,
  "temperature_key": "temperature",
  "response_path": "response"
}
```

## User Journey

1. User inputs testing concept or goal
2. LMTWT enables "hacker mode" with conversation history analysis
3. Load target configuration from JSON file
4. Attacker agent generates prompts designed to bypass safety mechanisms
5. LMTWT communicates with target AI and analyzes responses
6. The system learns from each attempt, improving attack effectiveness
7. Results are displayed and logged for further analysis

## API Keys

Create a `.env` file in the project root with your API keys:

```
GEMINI_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key
```

## Disclaimer

This tool is intended for educational purposes and legitimate security testing only. Always obtain proper authorization before testing AI systems. 