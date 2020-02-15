using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.Exceptions;

namespace FlightProject.POCOs
{
    public class Ticket : IPoco
    {
        public int Id { get; }
        public int FlightId { get; }
        public int CustomerId { get; }

        public Ticket()
        {
        }

        public Ticket(int flightId, int customerId)
        {
            FlightId = flightId;
            CustomerId = customerId;
        }

        internal Ticket(int id, int flightId, int customerId) : this(flightId, customerId)
        {
            Id = id;
        }

        public static bool operator ==(Ticket ticket, Ticket ticket1) => ticket.Equals(ticket1);

        public static bool operator !=(Ticket ticket, Ticket ticket1) => !(ticket == ticket1);

        public override bool Equals(object obj)
        {
            var ticket = obj as Ticket;
            return ticket.FlightId != 0 &&
                   ticket.CustomerId != 0 &&
                   FlightId == ticket.FlightId &&
                   CustomerId == ticket.CustomerId;
        }

        public override int GetHashCode()
        {
            return 6000000 + Id.GetHashCode();
        }
    }
}
