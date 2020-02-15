using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;

namespace FlightProject.DAOs
{
    internal interface ITicketDAO : IBasicDAO<Ticket>
    {
        int DoesTicketExistByCustomerAndFlight(Ticket ticket);
        Ticket GetTicketID(Ticket ticket);
        IList<Ticket> GetAllTicketsByFlight(int flightId);
        IList<Ticket> GetAllTicketsByCustomer(Customer customer);
    }
}
