using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;
using FlightProject.Exceptions;
using System.Data.SqlClient;

namespace FlightProject.Facades
{
    public class LoggedInCustomerFacade : AnonymousUserFacade, ILoggedInCustomerFacade
    {
        public new LoginToken<Customer> LoginToken { get; }

        internal LoggedInCustomerFacade(LoginToken<Customer> token)
        {
            LoginToken = token;
            _ticketDAO = new DAOs.TicketDAO();
            _flightDAO = new DAOs.FlightDAO();
        }

        public void CancelTicket(LoginToken<Customer> token, Ticket ticket)
        {
            if (token.CheckToken())
            {
                if (_ticketDAO.DoesTicketExistByCustomerAndFlight(ticket) == 1)
                {
                    _ticketDAO.Remove(ticket);
                }
                else
                {
                    throw new NullReferenceException("Requested ticket does not exist.");
                }
            }
        }

        public IList<Flight> GetAllMyFlights(LoginToken<Customer> token)
        {
            List<Flight> customerFlights = new List<Flight>();
            if (token.CheckToken())
            {
                customerFlights = (List<Flight>)_flightDAO.GetFlightsByCustomer(token.User);
            }
            return customerFlights;
        }

        public Ticket PurchaseTicket(LoginToken<Customer> token, int flightId)
        {
            Ticket ticket = new Ticket(flightId, token.User.Id);
            if (token.CheckToken())
            {
                if (_ticketDAO.DoesTicketExistByCustomerAndFlight(ticket) == 0)
                {
                    if ((_flightDAO.CheckRemainingSeatsOnFlight(flightId)) > 0)
                    {
                        _ticketDAO.Add(ticket);
                        _ticketDAO.GetTicketID(ticket);
                    }
                    else
                    {
                        throw new UnauthorizedActionException("No tickets remaining for this flight.");
                    }
                }
                else
                {
                    throw new UnauthorizedActionException("Customer already bought ticket for this flight.");
                }
            }

            if (ticket.FlightId == 0)
            {
                throw new NullResultException("Order Failed.");
            }
            return ticket;
        }

        public void ChangeMyPassword(LoginToken<Customer> token, string oldPassword, string newPassword)
        {
            if (token.CheckToken())
            {
                if (oldPassword == token.User.Password)
                {
                    Customer customer = new Customer(token.User.Id, token.User.FirstName, token.User.LastName, token.User.Username, newPassword, token.User.Address, token.User.PhoneNo, token.User.CreditCardNumber);
                    _customerDAO.Update(customer);
                    LoginToken.User = customer;
                }
                else
                {
                    throw new WrongPasswordException("Incorrect Password.");
                }
            }
        }

        public void ModifyCustomerDetails(LoginToken<Customer> token, Customer customer)
        {
            if (token.CheckToken())
            {
                if (token.User.Password == customer.Password)
                {
                    if (token.User.Username == customer.Username)
                    {
                        customer = new Customer(token.User.Id, customer.FirstName, customer.LastName, token.User.Username, token.User.Password, customer.Address, customer.PhoneNo, customer.CreditCardNumber);
                        _customerDAO.Update(customer);
                        LoginToken.User = customer;

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
    }
}
