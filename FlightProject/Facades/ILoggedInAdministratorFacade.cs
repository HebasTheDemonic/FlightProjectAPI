using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.Facades
{
    interface ILoggedInAdministratorFacade
    {
        LoginToken<Administrator> LoginToken { get; }
        void CreateNewAirline(LoginToken<Administrator> token, AirlineCompany airline);
        void UpdateAirlineDetails(LoginToken<Administrator> token, AirlineCompany airline);
        void RemoveAirline(LoginToken<Administrator> token, AirlineCompany airline);
        void CreateNewCustomer(LoginToken<Administrator> token, Customer customer);
        void UpdateCustomerDetails(LoginToken<Administrator> token, Customer customer);
        void RemoveCustomer(LoginToken<Administrator> token, Customer customer);
        void CreateNewAdministrator(LoginToken<Administrator> token, Administrator administrator);
        void UpdateAdministrator(LoginToken<Administrator> token, Administrator administrator);
        void RemoveAdministrator(LoginToken<Administrator> token, Administrator administrator);
        void CreateCountry(LoginToken<Administrator> token, Country country);
        void UpdateCountry(LoginToken<Administrator> token, Country country);
        void RemoveCountry(LoginToken<Administrator> token, Country country);
    }
}
