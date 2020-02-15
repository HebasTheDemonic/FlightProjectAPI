using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject
{
    public class LoginToken<T> where T : IUser
    {
        public T User { get; set; }

        public bool CheckToken()
        {
            if (this.User != null)
            {
                if (typeof(T) == this.User.GetType())
                {
                    return true;
                }
                throw new Exceptions.CorruptedDataException("Incorrect User type for requested token");
            }
            throw new Exceptions.CorruptedDataException("User Was Null.");
        }
    }
}
