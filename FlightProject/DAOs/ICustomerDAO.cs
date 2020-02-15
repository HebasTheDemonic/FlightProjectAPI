using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.DAOs
{
    internal interface ICustomerDAO : IBasicDAO<POCOs.Customer>
    {
        POCOs.Customer GetCustomerByUsername(string userName);
        int DoesCustomerExist(POCOs.Customer customer);
    }
}
