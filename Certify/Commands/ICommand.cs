using System.Collections.Generic;

namespace Certify.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}