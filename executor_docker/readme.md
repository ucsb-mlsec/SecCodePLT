```shell
cd executor_docker
```
## install dependencies

```shell
pip install -r requirements.txt
```

## update juliet dataset (if you updated the dataset)

```shell
cd docker/java-env
python update_dataset.py
```

## update seccodeplt json dataset

```shell
# TODO
```

## update docker image

```shell
cd docker/java-env
# if there are updates from the dataset, run this command to update the dataset
huggingface-cli download secmlr/SecCodePLT-Juliet --repo-type dataset --local-dir ./dataset
# build docker locally
docker build -t seccodeplt-juliet-java:latest .
# upload to Docker Hub
docker tag seccodeplt-juliet-java:latest yuzhounie/seccodeplt-juliet-java:latest
docker push yuzhounie/seccodeplt-juliet-java:latest
```

## run testing

```shell
cd docker/java-env

# build docker locally
huggingface-cli download secmlr/SecCodePLT-Juliet --repo-type dataset --local-dir ./dataset
docker build -t seccodeplt-juliet-java:latest .
# pull from Docker Hub
docker pull yuzhounie/seccodeplt-juliet-java:latest
# run docker
cd ..
python -m juliet_server --host 127.0.0.1 --port 8666 --image seccodeplt-juliet-java:latest

# some simple testing
cd ..
python evaluate_improved.py out_dir=./out/tmp tasks="[juliet_autocomplete]" models="[gpt4o]" batch_size=20 -cn evaluate_small
```