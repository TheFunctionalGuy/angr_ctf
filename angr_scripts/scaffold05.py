import angr
import claripy
import sys


def main(argv):
	path_to_binary = argv[1]
	project = angr.Project(path_to_binary)

	start_address = 0x08049318
	initial_state = project.factory.blank_state(
	    addr=start_address,
	    add_options={
	        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
	        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
	    })

	# The binary is calling scanf("%8s %8s %8s %8s").
	# (!)
	password_parts = [
	    claripy.BVS('password0', 8 * 8),
	    claripy.BVS('password1', 8 * 8),
	    claripy.BVS('password2', 8 * 8),
	    claripy.BVS('password3', 8 * 8),
	]

	# Determine the address of the global variable to which scanf writes the user
	# input. The function 'initial_state.memory.store(address, value)' will write
	# 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
	# 'address' parameter can also be a bitvector (and can be symbolic!).
	# (!)
	password_addresses = [0xba28f20, 0xba28f28, 0xba28f30, 0xba28f38]

	for password_address, password_part in zip(password_addresses,
	                                           password_parts):
		initial_state.memory.store(password_address, password_part)

	simulation = project.factory.simgr(initial_state)

	def is_successful(state):
		stdout_output = state.posix.dumps(sys.stdout.fileno())
		return 'Good Job.'.encode() in stdout_output

	def should_abort(state):
		stdout_output = state.posix.dumps(sys.stdout.fileno())
		return 'Try again.'.encode() in stdout_output

	simulation.explore(find=is_successful, avoid=should_abort)

	if simulation.found:
		solution_state = simulation.found[0]

		# Solve for the symbolic values. We are trying to solve for a string.
		# Therefore, we will use eval, with named parameter cast_to=bytes
		# which returns bytes that can be decoded to a string instead of an integer.
		# (!)
		solution = ' '.join([
		    solution_state.solver.eval(password_part, cast_to=bytes).decode()
		    for password_part in password_parts
		])

		print(solution)
	else:
		raise Exception('Could not find the solution')


if __name__ == '__main__':
	main(sys.argv)
