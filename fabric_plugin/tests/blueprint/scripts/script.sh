#!/bin/bash -e

test_run_script() {
    ctx instance runtime-properties test_value $test_value
}

test_run_script_from_url() {
    ctx instance runtime-properties test_value $test_value
}

test_run_script_default_base_dir() {
    ctx instance runtime-properties work_dir $PWD
}

test_run_script_process_config() {
    ctx instance runtime-properties env_value $test_value_env
    ctx instance runtime-properties bash_version $BASH_VERSION
    ctx instance runtime-properties arg1_value $1
    ctx instance runtime-properties arg2_value $2
    ctx instance runtime-properties cwd $PWD
    ctx instance runtime-properties ctx_path $(which ctx)
}

test_run_script_command_prefix() {
    ctx instance runtime-properties sanity sanity
    ctx instance runtime-properties bash_version $BASH_VERSION
}

test_run_script_reuse_existing_ctx_1() {
    ctx instance runtime-properties test_value $test_value
}

test_run_script_reuse_existing_ctx_2() {
    ctx instance runtime-properties test_value $test_value
}

test_run_script_return_value() {
    ctx returns $return_value
}

test_run_script_inputs_as_env_variables() {
    ctx returns "$custom_env_var"
}

test_run_script_inputs_as_env_variables_process_env_override() {
    ctx returns "$custom_env_var"
}

test_run_script_ctx_server_port() {
    ctx returns $CTX_SOCKET_URL
}

test_run_script_download_resource() {
    ctx returns $(cat $(ctx download-resource test_resource))
}

test_run_script_download_resource_and_render() {
    ctx returns $(cat $(ctx download-resource-and-render test_resource_render))
}

test_run_script_download_resource_explicit_target_path() {
    ctx download-resource test_resource /tmp/hello
    ctx returns $(cat /tmp/hello)
}

# Injected by test
${test_operation} $@
