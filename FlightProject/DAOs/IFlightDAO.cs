using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.DAOs
{
    internal interface IFlightDAO : IBasicDAO<Flight>
    {
        IList<Flight> GetFlightsByOriginCountry(int countryCode);
        IList<Flight> GetFlightsByDepartureDate(DateTime departureDate);
        IList<Flight> GetFlightsByLandingDate(DateTime landingDate);
        IList<Flight> GetFlightsByCustomer(Customer customer);
        IList<Flight> GetFlightsByAirlineCompany(AirlineCompany airline);
        IList<Flight> GetFlightsByDestinationCountry(int countryCode);
        int CheckRemainingSeatsOnFlight(int flightId);
        int DoesFlightExistByData(Flight flight);
        int DoesFlightExistById(int id);
    }
}
