using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject
{
    internal interface ILoginService
    {
        LoginEnum TryLogin(string userName);
        bool AdminLogin(string userName, string password, out LoginToken<POCOs.Administrator> loginToken);
        bool AirlineLogin(string userName, string password, out LoginToken<POCOs.AirlineCompany> loginToken);
        bool CustomerLogin(string userName, string password, out LoginToken<POCOs.Customer> loginToken);
    }
}
