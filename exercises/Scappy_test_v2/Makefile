BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = topology.json

include ../../utils/Makefile

shell:
	@for i in 1 2 3; do \
		xterm -e "python my_controller.py --switch-id $$i;bash" & \
	done
