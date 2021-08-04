using System;
using System.Collections.Generic;
using Certify.Commands;

namespace Certify
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // How To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //      a. That class must have a CommandName static property that has the Command's name
        //              and must also Implement the ICommand interface
        //      b. Put the code that does the work into the Execute() method
        //  2. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(CAs.CommandName, () => new CAs());
            _availableCommands.Add(Request.CommandName, () => new Request());
            _availableCommands.Add(Download.CommandName, () => new Download());
            _availableCommands.Add(Find.CommandName, () => new Find());
            _availableCommands.Add(PKIObjects.CommandName, () => new PKIObjects());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound= false;
            else
            {
                // Create the command object 
                var command = _availableCommands[commandName].Invoke();
                
                // and execute it with the arguments from the command line
                command.Execute(arguments);

                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}