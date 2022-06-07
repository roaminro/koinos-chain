#include <koinos/chain/resource_meter.hpp>
#include <koinos/chain/session.hpp>
#include <koinos/chain/exceptions.hpp>

#include <boost/multiprecision/cpp_int.hpp>

using int128_t = boost::multiprecision::int128_t;

namespace koinos::chain {

/*
 * Resource meter
 */

resource_meter::resource_meter()
{
   resource_limit_data initial_rld;

   initial_rld.set_disk_storage_limit( std::numeric_limits< uint64_t >::max() );
   initial_rld.set_network_bandwidth_limit( std::numeric_limits< uint64_t >::max() );
   initial_rld.set_compute_bandwidth_limit( std::numeric_limits< uint64_t >::max() );

   set_resource_limit_data( initial_rld );
}

resource_meter::~resource_meter() = default;

void resource_meter::set_resource_limit_data( const resource_limit_data& rld )
{
   _resource_limit_data           = rld;
   _disk_storage_remaining        = _resource_limit_data.disk_storage_limit();
   _system_disk_storage_used      = 0;
   _network_bandwidth_remaining   = _resource_limit_data.network_bandwidth_limit();
   _system_network_bandwidth_used = 0;
   _compute_bandwidth_remaining   = _resource_limit_data.compute_bandwidth_limit();
   _system_compute_bandwidth_used = 0;
}

void resource_meter::use_disk_storage( int64_t bytes )
{
   KOINOS_ASSERT( bytes <= int64_t( _disk_storage_remaining ), disk_storage_limit_exceeded, "disk storage limit exceeded" );

   if ( auto session = _session.lock() )
   {
      int128_t rc_cost = int128_t( bytes ) * _resource_limit_data.disk_storage_cost();
      KOINOS_ASSERT( rc_cost <= std::numeric_limits< int64_t >::max(), reversion_exception, "rc overflow" );
      session->use_rc( rc_cost.convert_to< int64_t >() );
   }
   else
   {
      _system_disk_storage_used += bytes;
   }

   if ( bytes >= 0 )
      _disk_storage_remaining -= uint64_t( bytes );
   else
      _disk_storage_remaining += uint64_t( -1 * bytes );
}

uint64_t resource_meter::disk_storage_used() const
{
   if ( _disk_storage_remaining > _resource_limit_data.disk_storage_limit() )
      return 0;

   return _resource_limit_data.disk_storage_limit() - _disk_storage_remaining;
}

uint64_t resource_meter::disk_storage_remaining() const
{
   if ( auto session = _session.lock() )
   {
      auto cost = _resource_limit_data.disk_storage_cost();

      if ( cost > 0 )
         return std::min( session->remaining_rc() / cost, _disk_storage_remaining );
   }

   return _disk_storage_remaining;
}

uint64_t resource_meter::system_disk_storage_used() const
{
   return std::max( 0ll, _system_disk_storage_used );
}

void resource_meter::use_network_bandwidth( int64_t bytes )
{
   KOINOS_ASSERT( bytes <= _network_bandwidth_remaining, network_bandwidth_limit_exceeded, "network bandwidth limit exceeded" );
   KOINOS_ASSERT( bytes >= 0, network_bandwidth_limit_exceeded, "cannot consume negative network bandwidth" );

   if ( auto session = _session.lock() )
   {
      int128_t rc_cost = int128_t( bytes ) * _resource_limit_data.network_bandwidth_cost();
      KOINOS_ASSERT( rc_cost <= std::numeric_limits< int64_t >::max(), reversion_exception, "rc overflow" );
      session->use_rc( rc_cost.convert_to< int64_t >() );
   }
   else
   {
      _system_network_bandwidth_used += bytes;
   }

   _network_bandwidth_remaining -= uint64_t( bytes );
}

uint64_t resource_meter::network_bandwidth_used() const
{
   return _resource_limit_data.network_bandwidth_limit() - _network_bandwidth_remaining;
}

uint64_t resource_meter::network_bandwidth_remaining() const
{
   if ( auto session = _session.lock() )
   {
      auto cost = _resource_limit_data.network_bandwidth_cost();

      if ( cost > 0 )
         return std::min( session->remaining_rc() / cost, _network_bandwidth_remaining );
   }

   return _network_bandwidth_remaining;
}

uint64_t resource_meter::system_network_bandwidth_used() const
{
   return std::max( 0ll, _system_network_bandwidth_used );
}

void resource_meter::use_compute_bandwidth( int64_t ticks )
{
   KOINOS_ASSERT( ticks <= _compute_bandwidth_remaining, compute_bandwidth_limit_exceeded, "compute bandwidth limit exceeded" );
   KOINOS_ASSERT( ticks >= 0, compute_bandwidth_limit_exceeded, "cannot consume compute bandwidth bandwidth" );

   if ( auto session = _session.lock() )
   {
      int128_t rc_cost = int128_t( ticks ) * _resource_limit_data.compute_bandwidth_cost();
      KOINOS_ASSERT( rc_cost <= std::numeric_limits< int64_t >::max(), reversion_exception, "rc overflow" );
      session->use_rc( rc_cost.convert_to< int64_t >() );
   }
   else
   {
      _system_compute_bandwidth_used += ticks;
   }

   _compute_bandwidth_remaining -= uint64_t( ticks );
}

uint64_t resource_meter::compute_bandwidth_used() const
{
   return _resource_limit_data.compute_bandwidth_limit() - _compute_bandwidth_remaining;
}

uint64_t resource_meter::compute_bandwidth_remaining() const
{
   if ( auto session = _session.lock() )
   {
      auto cost = _resource_limit_data.compute_bandwidth_cost();

      if ( cost > 0 )
         return std::min( session->remaining_rc() / cost, _compute_bandwidth_remaining );
   }

   return _compute_bandwidth_remaining;
}

uint64_t resource_meter::system_compute_bandwidth_used() const
{
   return std::max( 0ll, _system_compute_bandwidth_used );
}

void resource_meter::set_session( std::shared_ptr< abstract_rc_session > s )
{
   _session = s;
}

} // koinos::chain
