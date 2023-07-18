# How to: Apply patch sets from the LKML

1. locate the patch you want to apply, e.g.,
https://lore.kernel.org/lkml/20230319001535.23210-2-rick.p.edgecombe@intel.com/

2. get [b4](https://b4.docs.kernel.org/)

3. generate the mbox file for `git am`, e.g.,
`b4 am 20230319001535.23210-2-rick.p.edgecombe@intel.com`

4. move the generated .mbx file to the `mail_patch` directory

5. change the `commit` in `user.ini` to the base commit of the patch
set, e.g., `eeac8ede17557680855031c6f305ece2378af326`

6. add the name of the patch to the `am` option in the `user.ini`, e.g.,
`v8_20230318_rick_p_edgecombe_shadow_stacks_for_userspace.mbx`

6. (Optionally) Tune any kconfigs required to test the patch set

