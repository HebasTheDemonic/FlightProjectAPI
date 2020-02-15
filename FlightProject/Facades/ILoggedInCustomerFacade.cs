using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.Facades
{
    interface ILoggedInCustomerFacade
    {
        LoginToken<Customer> LoginToken { get; }
        IList<Flight> GetAllMyFlights(LoginToken<Customer> token);
        Ticket PurchaseTicket(LoginToken<Customer> token, int flightId);
        void CancelTicket(LoginToken<Customer> token, Ticket ticket);
        void ChangeMyPassword(LoginToken<Customer> token, string oldPassword, string newPassword); // test not implemented
        void ModifyCustomerDetails(LoginToken<Customer> token, Customer customer); // test not implemented
    }
}
