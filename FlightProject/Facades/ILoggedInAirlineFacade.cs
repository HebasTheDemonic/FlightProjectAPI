using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.Facades
{
    interface ILoggedInAirlineFacade
    {
        LoginToken<AirlineCompany> LoginToken { get; }
        IList<Ticket> GetAllTicketsByFlight(LoginToken<AirlineCompany> token, int flightId);
        IList<Flight> GetAllFlightsByAirline(LoginToken<AirlineCompany> token);
        void CancelFlight(LoginToken<AirlineCompany> token, int flightId);
        void CreateFlight(LoginToken<AirlineCompany> token, Flight flight);
        void UpdateFlight(LoginToken<AirlineCompany> token, int flightId, Flight flight);
        void ChangeMyPassword(LoginToken<AirlineCompany> token, string OldPassword, string NewPassword);
        void ModifyAirlineDetails(LoginToken<AirlineCompany> token, AirlineCompany airline);
    }
}
