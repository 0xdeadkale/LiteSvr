#!/usr/bin/env python3
"""Client module for BSLE capstone."""

from argparse import ArgumentParser

from interactive import ClientInteractive
from cmdline import ClientCmdline


def main():
    """Main method to run client, either interactively or by the CMD-LINE."""
    args, parser = _parse_arguments()

    count = 0
    for arg in args.__dict__:
        if args.__dict__[arg] is not None:
            count = count + 1

    if count == 2:
        ip_address = args.ip_address
        port = args.port
        try:
            ClientInteractive(ip_address, port).cmdloop()
        except (SystemExit, KeyboardInterrupt, GeneratorExit):
            print("\nExiting Interactive...")

    elif count == 5:
        ip_address = args.ip_address
        port = args.port
        user = args.user
        password = args.pwd
        cmd = args.command

        try:
            ClientCmdline(ip_address, port, user, password, cmd)
        except (SystemExit, KeyboardInterrupt, GeneratorExit):
            print("\nExiting cmd line...")
    else:
        parser.print_help()


def _parse_arguments():
    parser = ArgumentParser(description='FTP Client. All 5 args must be used. \
                        If only ip and port args, interactive shell triggers.',
                            epilog='Example: python3 client.py -i 127.0.0.1 \
                                    -p 53673 --user admin --pwd password \
                                    -c get fileonserver.txt filetoclient.txt')
    parser.add_argument('-i', '--ip_address', type=str,
                        help='IP address of server to connect to',
                        required=True)
    parser.add_argument('-p', '--port', type=int,
                        help='Port of server to connect to', required=True)

    parser.add_argument('--user', type=str,
                        help='Username used for login', required=False)

    parser.add_argument('--pwd', type=str,
                        help='Password of user', required=False)

    parser.add_argument('-c', '--command', type=str, nargs='+',
                        help='Command to server', required=False)

    args = parser.parse_args()

    return args, parser


if __name__ == '__main__':
    main()
