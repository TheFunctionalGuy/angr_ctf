# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.

import angr
import sys


def main(argv):
	project = angr.Project(argv[1])

	# Replace libc and glibc functions
	libc_functions = [
	    ('puts', 0x805ec90),
	    ('printf', 0x80512f0),
	    ('scanf', 0x8051340),
	]

	glibc_functions = [('__libc_start_main', 0x0804a250)]

	for func_name, address in libc_functions:
		project.hook(address, angr.SIM_PROCEDURES['libc'][func_name]())

	for func_name, address in glibc_functions:
		project.hook(0x0804a250, angr.SIM_PROCEDURES['glibc'][func_name]())

	start_address = 0x08049e1f
	initial_state = project.factory.blank_state(
	    addr=start_address,
	    add_options={
	        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
	        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
	    })

	simulation = project.factory.simulation_manager(initial_state,
	                                                veritesting=True)

	def is_successful(state):
		stdout_output = state.posix.dumps(sys.stdout.fileno())
		return 'Good Job.'.encode() in stdout_output

	def should_abort(state):
		stdout_output = state.posix.dumps(sys.stdout.fileno())
		return 'Try again.'.encode() in stdout_output

	simulation.explore(find=is_successful, avoid=should_abort)

	if simulation.found:
		solution_state = simulation.found[0]

		print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
	else:
		raise Exception('Could not find the solution')


if __name__ == '__main__':
	main(sys.argv)
