# nssp
Google Asylo
ASYLO's installation: https://asylo.dev/docs/guides/quickstart.html#getting-started-with-the-example-code 
docker pull gcr.io/asylo-framework/asylo
MY_PROJECT=~/asylo-examples
mkdir -p "${MY_PROJECT}"
wget -q -O - https://github.com/google/asylo-examples/archive/master.tar.gz | \
    tar -zxv --strip 1 --directory "${MY_PROJECT}"



a first example to check if everything works fine :
docker run -it --rm \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo \
    bazel run //quickstart:quickstart_sgx_sim -- --message="Asylo Rocks"
   
 an example of our project execution command for everything we have developped (md5,sha1, sha512, aes, rsa, diffie hellman):
 docker run -it --rm     -v bazel-cache:/root/.cache/bazel \  
 -v "/home/${USER}/our_code/asylo":/opt/my-project  \
 -w /opt/my-project     gcr.io/asylo-framework/asylo  \
 bazel run //network_security_semester_project:network_security_semester_project_sgx_sim -- --md5="STRING1" --sha1="STRING2" --sha512="STRING3" --aes="STRING4" --rsa="STRING5" --dh="STRING6"
