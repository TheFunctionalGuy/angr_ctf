import angr
import claripy
import sys

def main(argv):
	path_to_binary = argv[1]
	project = angr.Project(path_to_binary)

	start_address = 0x0804938f
	initial_state = project.factory.blank_state(
		addr=start_address,
		add_options = {
			angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
		}
	)

	# The binary is calling scanf("%8s %8s").
	# (!)
	password_parts = [
		claripy.BVS('password0', 8*8),
		claripy.BVS('password1', 8*8),
	]

	# Instead of telling the binary to write to the address of the memory
	# allocated with malloc, we can simply fake an address to any unused block of
	# memory and overwrite the pointer to the data. This will point the pointer
	# with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
	# Be aware, there is more than one pointer! Analyze the binary to determine
	# global location of each pointer.
	# Note: by default, Angr stores integers in memory with big-endianness. To
	# specify to use the endianness of your architecture, use the parameter
	# endness=project.arch.memory_endness. On x86, this is little-endian.
	# (!)
	#* These addresses have to be just in an unmapped memory region
	addresses = [
		(0xb34f878, 0x7000000),
		(0xb34f880, 0x7000010),
	]

	for pointer_to_malloc_memory_address, fake_heap_address in addresses:
		initial_state.memory.store(pointer_to_malloc_memory_address, fake_heap_address, endness=project.arch.memory_endness, size=4)

	# Store our symbolic values at our fake_heap_address. Look at the binary to
	# determine the offsets from the fake_heap_address where scanf writes.
	# (!)
	for (_, heap_address), password_part in zip(addresses, password_parts):
		initial_state.memory.store(heap_address, password_part)

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

		solution = ' '.join([solution_state.solver.eval(password_part, cast_to=bytes).decode() for password_part in password_parts])

		print(solution)
	else:
		raise Exception('Could not find the solution')

if __name__ == '__main__':
	main(sys.argv)
