# Makefile for collecting and installing requirements for nativeedge-plugins-sdk.
VENVS := $(shell pyenv virtualenvs --skip-aliases --bare | grep 'project\b')
FUSION_COMMON := fusion-common
FUSION_AGENT := fusion-agent
FUSION_MANAGER := fusion-manager
NATIVEEDGE_SDK := cloudify-utilities-plugins-sdk
INCUBATOR_DOMAIN := github.com/cloudify-incubator
BRANCH := master
SHELL := /bin/bash
DOMAIN=${GH_TOKEN}@github.com/fusion-e

default:
	make download_from_git
	make setup_local_virtual_env
	make run_tests

compile:
	make download_from_git
	make setup_local_virtual_env

download_from_git:
	make download_fusion_common
	make download_fusion_agent
	make download_fusion_manager
	make download_nativeedge_sdk

setup_local_virtual_env:
ifneq ($(VENVS),)
	@echo We have $(VENVS)
	pyenv virtualenv-delete -f project && pyenv deactivate
endif
	pyenv virtualenv 3.11 project

download_fusion_common:
ifneq ($(wildcard ${HOME}/${FUSION_COMMON}*),)
	@echo "Found ${HOME}/${FUSION_COMMON}."
else
	git clone --depth 1 https://${DOMAIN}/${FUSION_COMMON}.git ${HOME}/${FUSION_COMMON} -b ${BRANCH} && cd ${HOME}/${FUSION_COMMON} && cd
endif

download_fusion_agent:
ifneq ($(wildcard ${HOME}/${FUSION_AGENT}*),)
	@echo "Found ${HOME}/${FUSION_AGENT}."
else
	git clone --depth 1 https://${DOMAIN}/${FUSION_AGENT}.git ${HOME}/${FUSION_AGENT} -b ${BRANCH} && cd ${HOME}/${FUSION_AGENT} && cd
endif

download_fusion_manager:
ifneq ($(wildcard ${HOME}/${FUSION_MANAGER}*),)
	@echo "Found ${HOME}/${FUSION_MANAGER}."
else
	git clone --depth 1 https://${DOMAIN}/${FUSION_MANAGER}.git ${HOME}/${FUSION_MANAGER} -b ${BRANCH} && cd ${HOME}/${FUSION_MANAGER}/mgmtworker && cd
endif

download_nativeedge_sdk:
ifneq ($(wildcard ${HOME}/${NATIVEEDGE_SDK}*),)
	@echo "Found ${HOME}/${NATIVEEDGE_SDK}."
else
	git clone --depth 1 https://${INCUBATOR_DOMAIN}/${NATIVEEDGE_SDK}.git ${HOME}/${NATIVEEDGE_SDK} -b master && cd ${HOME}/${NATIVEEDGE_SDK} && cd
endif

cleanup:
	pyenv virtualenv-delete -f project
	rm -rf ${FUSION_MANAGER} ${FUSION_AGENT} ${FUSION_COMMON}

run_tests:
	@echo "Starting executing the tests."
	git submodule init
	git submodule update --remote --recursive | true
	HOME=${HOME} VIRTUAL_ENV=${HOME}/.pyenv/${VENVS} tox

clrf:
	@find . \( -path ./.tox -prune -o -path ./.git -prune \) -o -type f -exec dos2unix {} \;

wheels:
	@echo "Creating wheels..."
	@pip wheel ${HOME}/${FUSION_COMMON}/ -w /workspace/build/ --find-links /workspace/build
	@pip wheel ${HOME}/${FUSION_AGENT}/ -w /workspace/build/ --find-links /workspace/build
	@pip wheel ${HOME}/${FUSION_MANAGER}/mgmtworker -w /workspace/build/ --find-links /workspace/build
	@pip wheel ${HOME}/${NATIVEEDGE_SDK} -w /workspace/build/ --find-links /workspace/build