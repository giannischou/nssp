#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/logging.h"

#include "network_security_semester_project/CryptoSelection.pb.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave binary image to load");

ABSL_FLAG(std::string, sha1, "", "Message to encrypt with sha1");
ABSL_FLAG(std::string, sha512, "", "Message to encrypt with sha512");
ABSL_FLAG(std::string, md5, "", "Message to encrypt with md5");
ABSL_FLAG(std::string, rsa, "", "Message to encrypt-decrypt with rsa");
ABSL_FLAG(std::string, aes, "", "Message to encypt-decrypt with aes");
ABSL_FLAG(std::string, dh, "", "Keys exchanged with DH");


// Populates |enclave_input|->value() with |user_message|.
void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
  const std::string &user_message,
  guide::asylo::Demo::Action action) {
    guide::asylo::Demo *user_input = enclave_input->MutableExtension(guide::asylo::quickstart_input);
    user_input->set_value(user_message);
    user_input->set_action(action);
}


// Retrieves encrypted message from |output|. Intended to be used by the reader
// for completing the exercise.
const std::string GetEnclaveOutputMessage(const asylo::EnclaveOutput &output) {
  return output.GetExtension(guide::asylo::quickstart_output).value();
}


int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  constexpr char kEnclaveName[] = "trusted_enclave";

  const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, absl::GetFlag(FLAGS_md5).empty() &&
                absl::GetFlag(FLAGS_sha1).empty() &&
                absl::GetFlag(FLAGS_sha512).empty() &&
                absl::GetFlag(FLAGS_rsa).empty() &&
                absl::GetFlag(FLAGS_aes).empty() &&
                absl::GetFlag(FLAGS_dh).empty())
      << "At least one of the following flags should be specified: --sha1, --sha512, --md5, --rsa, --rsa, --aes, --dh. ";


  // Part 1: Initialization

  // Prepare |EnclaveManager| with default |EnclaveManagerOptions|
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";


  // Prepare |load_config| message.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);


  // Prepare |sgx_config| message.
  auto sgx_config = load_config.MutableExtension(asylo::sgx_load_config);
  sgx_config->set_debug(true);
  auto file_enclave_config = sgx_config->mutable_file_enclave_config();
  file_enclave_config->set_enclave_path(enclave_path);


  // Load Enclave with prepared |EnclaveManager| and |load_config| message.
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  auto status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;


  // Part 2: Secure execution

  // Prepare |input| with |message| and create |output| to retrieve response
  // from enclave.
  asylo::EnclaveInput input;
  asylo::EnclaveOutput output;


  // Get |EnclaveClient| for loaded enclave and execute |EnterAndRun|.
  asylo::EnclaveClient *const client = manager->GetClient(kEnclaveName);
  status = client->EnterAndRun(input, &output);

  if (!absl::GetFlag(FLAGS_md5).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_md5), guide::asylo::Demo::MD5);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypt with md5:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_sha1).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_sha1), guide::asylo::Demo::SHA1);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypt with sha1:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_sha512).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_sha512), guide::asylo::Demo::SHA512);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Encrypt with sha512:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_rsa).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_rsa), guide::asylo::Demo::RSA);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "RSA encryption - decryption:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }

  if (!absl::GetFlag(FLAGS_aes).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_aes), guide::asylo::Demo::AES);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "AES encryption - decryption:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }
  if (!absl::GetFlag(FLAGS_dh).empty()) {
    SetEnclaveUserMessage(&input, absl::GetFlag(FLAGS_dh), guide::asylo::Demo::DH);
    status = client->EnterAndRun(input, &output);
    LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;
    std::cout << "Diffie Hellman:" << std::endl
              << GetEnclaveOutputMessage(output) << std::endl;
  }


  // Part 3: Finalization

  // |DestroyEnclave| before exiting program.
  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}
