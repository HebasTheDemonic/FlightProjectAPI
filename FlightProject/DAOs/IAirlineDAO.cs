using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.DAOs
{
    internal interface IAirlineDAO : IBasicDAO<POCOs.AirlineCompany>
    {
        POCOs.AirlineCompany GetAirlineCompanybyUsername(string userName);
        IList<POCOs.AirlineCompany> GetAllAirlinesByCountry(int countryId);
        int DoesAirlineCompanyExist(POCOs.AirlineCompany airlineCompany);
    }
}
