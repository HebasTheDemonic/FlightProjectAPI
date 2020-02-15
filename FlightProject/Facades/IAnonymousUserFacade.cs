using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.Facades
{
    interface IAnonymousUserFacade
    {
        LoginToken<User> LoginToken { get; }
        IList<Flight> GetAllFlights();
        IList<AirlineCompany> GetAirlineCompanies();
        Flight GetFlightById(int id);
        IList<Flight> GetFlightsByOriginCountry(int CountryCode);
        IList<Flight> GetFlightsByDepartureDate(DateTime departureDate);
        IList<Flight> GetFlightsByLandingDate(DateTime landingTime);
        IList<Country> GetAllCountries();
        Country GetCountryById(int id);
        void CreateNewCustomer(Customer customer); // test not implemented
    }
}
