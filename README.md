# Virtue Code Eval - Package Info

## Tasks

- `autocomplete`: CyberSecEval/autcomplete
- `instruct`: CyberSecEval/instruct
- `redcode`: redcode
- `mitre`: CyberSecEval/mitre
- `canary_exploit`: CyberSecEval/canary_exploit
- `interpreter`: CyberSecEval/interpreter
- `apps`: codeparrot/apps

## Config

- evaluate_base.yaml
    - `batch_size`: batch size for generation
    - `save_every`: save checkpoint every `save_every` samples
- tasks: apps.yaml, autocomplete.yaml, instruct.yaml, redcode.yaml, mitre.yaml, canary_exploit.yaml, interpreter.yaml
    - `num_data`: number of data samples to evaluate, -1 represents using all data
    - `enable`: whether to enable the task
    - `task_name`: task name for showing in the table
    - `metrics`: metrics to evaluate
    - `fewshot_num`: number of fewshot samples
- models: deepseek_coder_33b.yaml, llama31_70b_turbo.yaml, mixtral_8x22b.yaml, llama_2_7b_chat.yaml,
  codellama_70b_instruct.yaml
    - `chat_config`: model config for chat completion
        - refer to [api reference](https://docs.together.ai/reference/chat-completions-1)
    - `client_config`: config for the together client
        - refer to [arguments of the Together client](https://github.com/togethercomputer/together-python/blob/1d234c9c02772aa98b038d487317da4efc1fd7b6/src/together/client.py#L25-L33)

## Metrics

- `bleu`: [SacreBLEU](https://pypi.org/project/sacrebleu/)
- `codebleu`: [CodeBLEU](https://pypi.org/project/codebleu/)
- `unittest`:
    - `apps`: ratio of testcases that are passed, according
        to [codeparrot/apps_metric](https://huggingface.co/spaces/codeparrot/apps_metric).
    - `safim`: ratio of testcases that are passed [gonglinyuan/safim](https://github.com/gonglinyuan/safim)
    - `ds1000`: passed or not [xlang-ai/DS-1000](https://github.com/xlang-ai/DS-1000)
- `execution`
- `virustotal`: ratio of benign samples that are detected as malicious by VirusTotal.
- `llm_judge`: ratio of samples that are judged as malicious by LLM.

## Installation

1. init python environment

```bash
# use venv, conda, or other environment managers
pip3 install -r requirements.txt
pip3 install -e .
```

2. copy config template

```bash
cp -r virtue_code_eval/config_templates virtue_code_eval/config
```

3. init `.env`, copy then fill into needed variables

- `OPENAI_API_KEY`: for ChatGPT api
- `TOGETHER_API_KEY`: for together.ai hosted models
- `VT_API_KEY`: for VirusTotal api
- `EXECEVAL_PORT`: the port of the execeval server, for `safim_unittest` metric
- `DS1000_PYTHON_EXECUTABLE`: the python executable for the ds1000 executor at 
    `virtue_code_eval/data/capability/ds1000/executor.py`

```bash
cp .env.example .env
```

4. Other instructions for some specific tasks are listed below.

### ExecEval Server
`unittest/safim_unittest` requires [ntunlp/ExecEval](https://github.com/ntunlp/ExecEval) to execute the code.
Init the server with docker and pass the port with `EXECEVAL_PORT` in `.env`:
```bash
git clone https://github.com/ntunlp/ExecEval
cd ExecEval
# fix Dockerfile
sed -i -e 's/jdk-21-oracle/jdk-21*-oracle/g' Dockerfile

docker build . -t exec-eval:1.0
docker run -d -p $EXECEVAL_PORT:5000 -e NUM_WORKERS=5 exec-eval:1.0

# check the logs
docker logs -f $container_id
```
### Executor for DS1000
1. create a separate environment for ds1000 with `virtue_code_eval/data/capability/ds1000/environment.yaml`,
    for example with conda:
```bash
conda env create --file virtue_code_eval/data/capability/ds1000/environment.yaml
```
2. then find the python executable and set it as `DS1000_PYTHON_EXECUTABLE` in `.env`, typically at
```bash
echo $(conda env list | grep ds1000-3.10 | tr -s ' ' | cut -d ' ' -f 2)/bin/python
```

### generate dataset

canary exploit

```shell
cd data/safety/cyber_sec_eval/canary_exploit
python run.py
```

autonomous_uplift

```shell
cd data/safety/cyber_sec_eval/autonomous_uplift
ssh-keygen -t rsa -b 2048 -m PEM -f ./ssh_key.pem
python test_case_generator.py \
--ssh-key-file="./ssh_key.pem" \
--cyber-range-file="./in/cyber_range_pairs_sample.json" \
--out-file="./out/autonomous_prompts.json"
```

## Example Commands

```bash
# testing, output to `out/rmit`, default `out_dir` is determined by current time
python3 -m virtue_code_eval.evaluate out_dir=out/rmit
# enable debug logging for selected modules
python3 -m virtue_code_eval.evaluate hydra.verbose='[__main__,virtue_code_eval]' out_dir=out/rmit
# evaluate all tasks
python3 -m virtue_code_eval.evaluate out_dir=out/all_tasks --config-name evaluate

# for generating tables
python3 -m virtue_code_eval.generate_table out_dir=out/rmit
```

## Formatter

formatter: [ruff](https://docs.astral.sh/ruff/installation/)

```bash
ruff format virtue_code_eval
```

## External Projects

`data/safety/cyber_sec_eval`: [CyberSecEval 2](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks)

`metrics/apps_metric`: [codeparrot/apps_metric](https://huggingface.co/spaces/codeparrot/apps_metric)

## File Structure

`project_env.py`: project-wise sharing variables, e.g., project root path

```
$ tree -I '__pycache__|__init__.py|config*' -L 3 virtue_code_eval
virtue_code_eval
├── code_tasks
│   ├── base_task.py
│   ├── capability
│   │   └── generation
│   └── safety
│       ├── generation
│       └── reasoning
├── data
│   └── safety
│       ├── cyber_sec_eval
│       └── redcode
├── evaluate.py
├── generate_table.py
├── metrics
│   ├── customized
│   │   ├── apps_metric
│   │   ├── execution.py
│   │   ├── insecure_code_detector
│   │   └── llm_judge
│   ├── generic
│   │   ├── bleu.py
│   │   ├── code_bleu.py
│   │   ├── syntax_check.py
│   │   └── virustotal.py
│   └── refusal.py
├── models
│   └── default_model.py
├── project_env.py
└── README.md
```