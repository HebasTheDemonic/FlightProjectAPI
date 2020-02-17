using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.POCOs
{
    public class User : IUser
    {
        public string Username { get; }
        public string Password { get; }

        public User()
        {

        }

        public User(string username, string password)
        {
            Username = username ?? throw new ArgumentNullException(nameof(username));
            Password = password ?? throw new ArgumentNullException(nameof(password));
        }
    }
}
