# LMTWT - Let Me Talk With Them

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen" alt="Contributions: Welcome">
</p>

LMTWT is a powerful security testing framework for evaluating AI model resistance to prompt injection attacks and other security vulnerabilities. It enables security researchers to use one AI model (e.g., Gemini) to test the security boundaries of another AI system.

## 🔥 Key Features

- **Multi-Model Testing**: Test against OpenAI, Anthropic, Gemini, and custom API endpoints
- **Advanced Attack Modes**: 
  - **Hacker Mode** with conversation history analysis
  - **Probe Attacks** across multiple vulnerability categories
  - **Template-based** testing patterns
- **Extensible Architecture**:
  - Local model support via Hugging Face
  - Custom API endpoints
  - Pluggable attack strategies
- **Developer Experience**:
  - Modern Web UI
  - Interactive CLI
  - Detailed reporting
- **Performance Optimizations**:
  - GPU acceleration (CUDA/MPS)
  - Circuit breaker patterns to respect rate limits
  - Model quantization for resource efficiency

## 📋 Installation

```bash
# Clone the repository
git clone https://github.com/tanuphattin/LMTWT.git
cd LMTWT

# Install dependencies
pip install -r requirements.txt

# Optional: GPU acceleration
# For NVIDIA GPUs
pip install torch==2.1.0+cu118 -f https://download.pytorch.org/whl/torch_stable.html
pip install bitsandbytes accelerate

# For Apple Silicon (M1/M2/M3)
pip install torch
```

## 🚀 Quick Start

```bash
# Set up your API keys in .env file (see .env.example)
cp .env.example .env

# Run interactive mode (Gemini attacking OpenAI)
./run.sh --attacker gemini --target openai --mode interactive

# Launch the web UI
./run.sh --web
```

## 💡 Usage Examples

### Testing Different Models

```bash
# Test against Claude
./run.sh --attacker gemini --target anthropic

# Use a local model as the target
./run.sh --attacker gemini --target huggingface --target-model "mistralai/Mistral-7B-Instruct-v0.2"

# Test against a custom API
./run.sh --attacker gemini --target external-api --target-config examples/custom_target.json
```

### Attack Modes

```bash
# Enable hacker mode for adaptive attacks
./run.sh --attacker gemini --target openai --hacker-mode

# Use probe mode to test specific vulnerabilities
./run.sh --probe-mode --probe-category injection --target openai

# Run batch attacks with custom instructions
./run.sh --mode batch --instruction "Create a jailbreak prompt" --instruction "Test system prompt extraction"
```

### Advanced Options

```bash
# Run in probe mode with a specific attack category
./run.sh --probe-mode --probe-category dan --probe-iterations 10

# Use templates for standardized testing
./run.sh --mode template --template basic_prompt_injection

# List available templates
./run.sh --list-templates
```

## 🧩 Attack Categories

LMTWT supports multiple attack categories to test different aspects of AI safety:

| Category | Description |
|----------|-------------|
| `dan` | Do Anything Now jailbreak prompts |
| `injection` | Classic prompt injection attacks |
| `xss` | Cross-site scripting vectors |
| `glitch` | Unicode and token boundary exploits |
| `misleading` | Misleading information generation |
| `malware` | Malware-related content generation |
| `forbidden_knowledge` | Dangerous knowledge extraction |
| `snowball` | Escalating hallucination attacks |

## 🌐 Web UI

Launch the modern web interface:

```bash
# Start on default port (8501)
./run.sh --web

# Custom port and public sharing
./run.sh --web --web-port 8080 --share
```

The UI provides:
- Model selection and configuration
- Interactive attack testing
- Result visualization and analysis
- Attack history with success tracking

## 🔌 Configuration

Create a `.env` file with your API keys:

```
GEMINI_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key
HUGGINGFACE_API_KEY=your_huggingface_api_key  # Optional
```

## 📝 License

This project is available under the MIT License - see the LICENSE file for details.

### Acknowledgments

This project was inspired by several open source tools in the LLM security space, including:

- [NVIDIA's garak](https://github.com/NVIDIA/garak) (Apache License 2.0) - A pioneering tool for LLM vulnerability scanning that informed some of our testing strategies.

While LMTWT is an original implementation under the MIT License, we appreciate the work of these projects that have advanced the field of AI security research.

## 💖 Support the Project

If you find this tool valuable, please consider supporting its development:

<p align="center">
  <a href="https://www.paypal.me/tanuphattin">
    <img src="https://img.shields.io/badge/Donate-PayPal-blue.svg?style=for-the-badge" alt="PayPal">
  </a>
</p>

Your contributions help maintain this project and fund future development.

## ⚠️ Disclaimer

This tool is intended for *educational purposes* and *legitimate security testing* only. Always obtain proper authorization before testing AI systems. The creators are not responsible for misuse of this software.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Automated Testing

This project uses pytest for testing and GitHub Actions for continuous integration:

```bash
# Install development dependencies
pip install pytest pytest-cov

# Run tests
pytest

# Run tests with coverage report
pytest --cov=src/lmtwt
```

[![Python Tests](https://github.com/tanuphattin/LMTWT/actions/workflows/python-tests.yml/badge.svg)](https://github.com/tanuphattin/LMTWT/actions/workflows/python-tests.yml)

## 📬 Contact

Tanuphat Tin - tanuphat.chai@gmail.com

Project Link: [https://github.com/tanuphattin/LMTWT](https://github.com/tanuphattin/LMTWT) 
