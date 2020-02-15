using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.DAOs
{
    internal interface IGeneralDAO
    {
        void CleanFlightList();
        void DBTestPrep();
        int DoesUsernameExist(string userName);
        void DBClear();
        int TryLogin(string username);
    }
}
