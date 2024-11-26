# Trivy EPSS Plugin

A Trivy plugin that enriches vulnerability scan results with EPSS (Exploit Prediction Scoring System) data from FIRST.org.

## Overview

This plugin adds EPSS scores to Trivy vulnerability scan results, helping security teams prioritize vulnerabilities based on their likelihood of being exploited in the wild.

EPSS (Exploit Prediction Scoring System) is a data-driven effort for estimating the probability that a software vulnerability will be exploited in the wild.

## Features

- Fetches EPSS scores from FIRST.org API
- Processes CVEs in batches to respect API limits
- Adds three key EPSS metrics to each vulnerability:
  - `epss_score`: Probability of exploitation (0-1)
  - `epss_percentile`: Relative ranking compared to other CVEs
  - `epss_date`: Date of the EPSS score

## Installation

1. Build and install the plugin:
```bash
trivy plugin install github.com/AFRAID-rocks/trivy_plugin_epss
```

2. Verify installation:
```bash
trivy plugin list
```

## Usage

Run Trivy with the plugin:
```bash
trivy <target> --format json --output plugin=trivy_plugin_epss [--output-plugin-arg plugin_flags] <target_name>
```
Or:
```bash
trivy <target> -f json <target_name> | trivy trivy_plugin_epss [plugin_flags]
```

## Output Format

The plugin adds EPSS data to each vulnerability in the following format:
```json
{
  "VulnerabilityID": "CVE-2022-1234",
  "Custom": {
    "epss_score": 0.12345,
    "epss_percentile": 0.89012,
    "epss_date": "2024-01-15",
    "epss_source": "FIRST.org"
  }
  // ... other vulnerability fields ...
}
```

## Interpretation of Results

- `epss_score`: Ranges from 0 to 1, representing the probability that a vulnerability will be exploited
  - Example: A score of 0.12345 means there's a 12.345% probability of exploitation
- `epss_percentile`: Indicates how the vulnerability ranks compared to others
  - Example: 0.89012 means this CVE is more likely to be exploited than 89.012% of known vulnerabilities

## Requirements

- Trivy v0.45.0 or higher
- Go 1.20 or higher (for building)
- Internet access to reach FIRST.org API

## Building from Source

```bash
# Clone the repository
git clone https://github.com/AFRAID-rocks/trivy_plugin_epss
cd trivy_plugin_epss

# Build and install
make all
```

## Uninstallation

```bash
make uninstall
```

## License

blabla

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- EPSS data provided by [FIRST.org](https://www.first.org/epss/)
- Built for [Trivy](https://github.com/aquasecurity/trivy)
