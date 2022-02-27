load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@com_google_asylo//asylo/bazel:asylo.bzl", "cc_unsigned_enclave", "debug_sign_enclave", "enclave_loader")


licenses(["notice"])

package(
    default_visibility = [
        "@com_google_asylo//asylo:implementation",
    ],
)

# Example and exercise for using Asylo toolkits.
proto_library(
    name = "CryptoSelection_proto",
    srcs = ["CryptoSelection.proto"],
    deps = ["@com_google_asylo//asylo:enclave_proto"],
)

cc_proto_library(
    name = "CryptoSelection_cc_proto",
    deps = [":CryptoSelection_proto"],
)

cc_unsigned_enclave(
    name = "CryptoFunctions_unsigned.so",
    srcs = ["CryptoFunctions.cc"],
    deps = [
        ":CryptoSelection_cc_proto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo:enclave_runtime",
        "@com_google_asylo//asylo/crypto:aead_cryptor",
        "@com_google_asylo//asylo/util:cleansing_types",
        "@com_google_asylo//asylo/util:status",
    ],
)

debug_sign_enclave(
    name = "CryptoFunctions.so",
    unsigned = "CryptoFunctions_unsigned.so",
)

enclave_loader(
    name = "network_security_semester_project",
    srcs = ["CryptoMain.cc"],
    backends = sgx.backend_labels,  # Has SGX loader dependencies  
    enclaves = {"enclave": ":CryptoFunctions.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":CryptoSelection_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_asylo//asylo:enclave_cc_proto",
        "@com_google_asylo//asylo:enclave_client",
        "@com_google_asylo//asylo/util:logging",
    ] + select(
        {
            "@linux_sgx//:sgx_hw": ["@com_google_asylo//asylo/platform/primitives/sgx:loader_cc_proto"],
            "@linux_sgx//:sgx_sim": ["@com_google_asylo//asylo/platform/primitives/sgx:loader_cc_proto"],
        },
        no_match_error = "network_security_semester_project",
    ),
)
