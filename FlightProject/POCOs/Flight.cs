using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.Exceptions;

namespace FlightProject.POCOs
{
    public class Flight : IPoco
    {
        public int Id { get; }
        public int AirlineCompanyId { get; }
        public int OriginCountryId { get; }
        public int DestinationCountryId { get; }
        public DateTime DepartureTime { get; }
        public DateTime LandingTime { get; }
        public string FlightStatus { get; }
        public int TotalTickets { get; }
        public int RemainingTickets { get; }

        public Flight()
        {
        }

        public Flight(int airlineCompanyId, int originCountryId, int destinationCountryId, DateTime departureTime, DateTime landingTime, int totalTickets)
        {
            AirlineCompanyId = airlineCompanyId;
            OriginCountryId = originCountryId;
            DestinationCountryId = destinationCountryId;
            DepartureTime = departureTime;
            LandingTime = landingTime;
            TotalTickets = totalTickets;
        }

        internal Flight(int id, int airlineCompanyId, int originCountryId, int destinationCountryId, DateTime departureTime, DateTime landingTime, string flightStatus, int totalTickets, int remainingTickets) : this(airlineCompanyId, originCountryId, destinationCountryId, departureTime, landingTime, totalTickets)
        {
            Id = id;
            FlightStatus = flightStatus ?? throw new ArgumentNullException(nameof(flightStatus));
            RemainingTickets = remainingTickets;
        }

        public static bool operator ==(Flight flight, Flight flight1) => flight.Equals(flight1);

        public static bool operator !=(Flight flight, Flight flight1) => !(flight == flight1);

        public override bool Equals(object obj)
        {
            var flight = obj as Flight;
            return flight != null &&
                   AirlineCompanyId == flight.Id &&
                   OriginCountryId == flight.OriginCountryId &&
                   DestinationCountryId == flight.DestinationCountryId;
        }

        public override int GetHashCode()
        {
            return 5000000 + Id.GetHashCode();
        }
    }
}
