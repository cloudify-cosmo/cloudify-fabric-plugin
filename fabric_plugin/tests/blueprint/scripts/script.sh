#!/bin/bash -e

ctx logger info "It works!!!"
ctx logger info "instance id: $(ctx instance id)"
ctx logger info "task name: $(ctx task-name)"
ctx logger info "some_env_var: $some_env_var"
ctx logger info "cwd: $PWD"
ctx logger info "arg0: $0"
ctx logger info "arg1: $1"
ctx logger info "arg2: $2"
