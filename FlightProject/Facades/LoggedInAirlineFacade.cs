using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;
using FlightProject.Exceptions;
using FlightProject.DAOs;
using System.Data.SqlClient;

namespace FlightProject.Facades
{
    public class LoggedInAirlineFacade : AnonymousUserFacade, ILoggedInAirlineFacade
    {
        public new LoginToken<AirlineCompany> LoginToken { get; }

        internal LoggedInAirlineFacade(LoginToken<AirlineCompany> token)
        {
            LoginToken = token;
            _ticketDAO = new TicketDAO();
            _flightDAO = new FlightDAO();
            _airlineDAO = new AirlineDAO();
        }

        public void CancelFlight(LoginToken<AirlineCompany> token, int flightId)
        {
            if (token.CheckToken())
            {
                if (_flightDAO.DoesFlightExistById(flightId) == 1)
                {
                    Flight flight = _flightDAO.Get(flightId);
                    if (flight.AirlineCompanyId != token.User.Id)
                    {
                        throw new UnauthorizedActionException("Cannot cancel flights of other companies.");
                    }
                    List<Ticket> tickets = (List<Ticket>)_ticketDAO.GetAllTicketsByFlight(flightId);
                    foreach (Ticket ticket in tickets)
                    {
                        _ticketDAO.Remove(ticket);
                    }
                    _flightDAO.Remove(flight);
                }
                else
                {
                    throw new NullReferenceException("Flight not found.");
                }
            }
        }

        public void ChangeMyPassword(LoginToken<AirlineCompany> token, string OldPassword, string NewPassword)
        {
            if (token.CheckToken())
            {
                if (OldPassword == token.User.Password)
                {
                    AirlineCompany airlineCompany = new AirlineCompany(token.User.Id, token.User.AirlineName, token.User.UserName, NewPassword, token.User.OriginCountry);
                    _airlineDAO.Update(airlineCompany);
                    token.User = airlineCompany;
                }
                else
                {
                    throw new WrongPasswordException("Incorrect Password.");
                }
            }
        }

        public void CreateFlight(LoginToken<AirlineCompany> token, Flight flight)
        {
            if (token.CheckToken())
            {
                if (_flightDAO.DoesFlightExistByData(flight) == 0)
                {
                    _flightDAO.Add(flight);
                }
                else
                {
                    throw new DataAlreadyExistsException("Flight Already Exists");
                }
            }
        }

        public IList<Flight> GetAllFlightsByAirline(LoginToken<AirlineCompany> token)
        {
            List<Flight> allFlightsOfCompany = new List<Flight>();

            if (token.CheckToken())
            {
                allFlightsOfCompany = (List<Flight>)_flightDAO.GetFlightsByAirlineCompany(token.User);
            }

            return allFlightsOfCompany;
        }

        public IList<Ticket> GetAllTicketsByFlight(LoginToken<AirlineCompany> token, int flightId)
        {
            List<Ticket> tickets = new List<Ticket>();

            if (token.CheckToken())
            {
                if (_flightDAO.DoesFlightExistById(flightId) == 1)
                {
                    if (_flightDAO.Get(flightId).AirlineCompanyId == token.User.Id)
                    {
                        tickets = (List<Ticket>)_ticketDAO.GetAllTicketsByFlight(flightId);
                    }
                    else
                    {
                        throw new UnauthorizedActionException("Cannot see flights of other companies.");
                    }
                }
                else
                {
                    throw new NullReferenceException("Flight not found");
                }
            }
            return tickets;
        }

        public void ModifyAirlineDetails(LoginToken<AirlineCompany> token, AirlineCompany airline)
        {
            if (token.CheckToken())
            {
                if (token.User.Password == airline.Password)
                {
                    if (token.User.UserName == airline.UserName)
                    {
                        try
                        {
                            airline = new AirlineCompany(token.User.Id, airline.AirlineName, airline.UserName, token.User.Password, airline.OriginCountry);
                            _airlineDAO.Update(airline);
                            token.User = airline;
                        }
                        catch (SqlException sqlEx)
                        {
                            throw new UnregisteredDataException("Country not Recognized.", sqlEx);
                        }
                    }
                    else
                    {
                        throw new UnauthorizedActionException("Usernames cannot be changed.");
                    }
                }
                else
                {
                    throw new WrongPasswordException("Incorrect Password.");
                }
            }
        }

        public void UpdateFlight(LoginToken<AirlineCompany> token, int flightId, Flight flight)
        {
            if (token.CheckToken())
            {

                if (_flightDAO.DoesFlightExistById(flightId) == 1)
                {
                    Flight oldFlightDetails = _flightDAO.Get(flightId);
                    if (oldFlightDetails.AirlineCompanyId != flight.AirlineCompanyId)
                    {
                        throw new UnauthorizedActionException("Cannot make changes to flights of other companies");
                    }
                    int newAmount = oldFlightDetails.RemainingTickets + (flight.TotalTickets - oldFlightDetails.TotalTickets);
                    flight = new Flight(oldFlightDetails.Id, oldFlightDetails.AirlineCompanyId, oldFlightDetails.OriginCountryId, oldFlightDetails.DestinationCountryId, flight.DepartureTime, flight.LandingTime, oldFlightDetails.FlightStatus, flight.TotalTickets, newAmount);
                    _flightDAO.Update(flight);
                }
                else
                {
                    throw new NullReferenceException("Flight not found.");
                }
            }
        }
    }
}
