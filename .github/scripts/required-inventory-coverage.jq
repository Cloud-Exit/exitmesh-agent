(.targets[0].last_health.coverage // []) as $coverage |
all(["Secret|", "ConfigMap|", "inventory.exitmesh.io/CustomResourceDiscovery|"][];
  . as $prefix |
  [$coverage[] | select(.key | startswith($prefix))] |
  length > 0 and all(.[]; .state == "complete"))
