using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.DAOs
{
    internal interface IAdministratorDAO : IBasicDAO<POCOs.Administrator>
    {
        POCOs.Administrator GetAdministratorByUsername(string username);
        int DoesAdministratorExist(POCOs.Administrator administrator);
    }
}
