To generate the sample networking-sfc configuration files and
the sample policy file, run the following commands respectively
from the top level of the networking-sfc directory:

  tox -e genconfig
  tox -e genpolicy

If a 'tox' environment is unavailable, then you can run
the following commands respectively
instead to generate the configuration files:

  oslo-config-generator --config-file etc/oslo-config-generator/networking-sfc.conf
  oslopolicy-sample-generator --config-file=etc/oslo-policy-generator/policy.conf
