# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import sys

def main(argv):
	project = angr.Project(argv[1])

	initial_state = project.factory.entry_state(
		add_options = {
			angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
		}
	)

	simulation = project.factory.simgr(initial_state, veritesting=True)
	simulation.explore(find=0x0804937b)

	if simulation.found:
		solution_state = simulation.found[0]

		print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
	else:
		raise Exception('Could not find the solution')

if __name__ == '__main__':
	main(sys.argv)
